package service

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/threat"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/trivy"
	"go.uber.org/zap"
)

// EventFound is published once at the end of a pass that found a critical vulnerability, that
// attackers are not known to exploit, not told yet in an app an update is offered for. Its
// properties: "apps", the names joined by ", ", and "count", how many such vulnerabilities
// there are in all.
const EventFound = "vuln:found"

// EventExploited is EventFound for the vulnerabilities (critical or high) attackers already
// exploit, by the lists in use. A vulnerability told by it is not told by EventFound.
const EventExploited = "vuln:exploited"

var (
	ErrRunning = errors.New("a scan is already running")
	ErrNoApp   = errors.New("no app of that name on this box")
)

// roomMargin is what must stay free beside the copy of the image Trivy makes, and
// roomDatabase what the vulnerability database takes (1.7 GB measured), which the first
// scan of a box downloads.
const (
	roomMargin   = 1 << 30
	roomDatabase = 2 << 30
)

type imageScanner interface {
	Scan(ctx context.Context, image string, osOnly bool) ([]byte, error)
	DBUpdatedAt() (time.Time, error)
}

// Scanner scans the images of the box, one at a time, and keeps what it found.
type Scanner struct {
	Docker Docker
	Trivy  imageScanner
	// Busy says whether something runs on the apps (an update, a backup): the scan waits.
	Busy func(ctx context.Context) (bool, error)
	// Updates says, by app, whether an update of the app is offered.
	Updates func(ctx context.Context) (map[string]bool, error)
	// Free is the room left in a folder, in bytes.
	Free func(dir string) (uint64, error)
	// Threat is the lists of exploited vulnerabilities in use; nil, or nil lists, when there
	// are none.
	Threat func() *threat.Lists
	// Publish sends an event to the message bus.
	Publish func(name string, properties map[string]string) error
	Now     func() time.Time
	// Dir keeps the results.
	Dir string
	// TmpDir is the folder Trivy copies an image to the first time it scans it. It is this
	// service's alone: every pass empties it. It is asked at each pass because where it is
	// can depend on Docker, which may not answer yet when the service starts.
	TmpDir func(ctx context.Context) (string, error)
	// BusyWait is the time between two questions to Busy, and BusyLimit when the pass gives
	// up. Zero is a minute and two hours.
	BusyWait, BusyLimit time.Duration

	load    sync.Once
	mu      sync.Mutex // guards what follows
	running bool
	state   State

	trivyOnce sync.Once
	trivy     chan struct{} // holds one token: whoever has it runs Trivy
}

// withTrivy runs do with the only token to run Trivy: two Trivy at once would fight over the
// temporary folder and the disk. It gives up with ctx's error when ctx ends before the token
// is free.
func (s *Scanner) withTrivy(ctx context.Context, do func() error) error {
	s.trivyOnce.Do(func() { s.trivy = make(chan struct{}, 1) })
	select {
	case s.trivy <- struct{}{}:
		defer func() { <-s.trivy }()
		return do()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Scanner) loaded() {
	s.load.Do(func() {
		state := Load(s.Dir)
		s.mu.Lock()
		s.state = state
		s.mu.Unlock()
	})
}

func (s *Scanner) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.running
}

// Snapshot is what the last pass left: the results and the images they are about.
func (s *Scanner) Snapshot() (State, []Image) {
	s.loaded()
	s.mu.Lock()
	defer s.mu.Unlock()

	state := s.state
	state.Images, state.Told, state.ToldExploited = maps.Clone(s.state.Images), maps.Clone(s.state.Told), maps.Clone(s.state.ToldExploited)

	return state, slices.Clone(s.state.Inventory)
}

// Pass scans every image once. It returns ErrRunning when a pass runs already, and nil
// otherwise: what went wrong is kept as the state's LastError, beside the results.
func (s *Scanner) Pass(ctx context.Context) error {
	if !s.begin() {
		return ErrRunning
	}
	s.run(ctx, "")

	return nil
}

// Start runs a pass in the background; false when one runs already.
func (s *Scanner) Start(ctx context.Context) bool {
	if !s.begin() {
		return false
	}
	go s.run(ctx, "")

	return true
}

// StartApp scans again, in the background, the images of one app only: after a fix to it,
// the administrator need not wait for every other image. It is ErrNoApp for a name the last
// pass did not see and ErrRunning when a pass runs already; it shares their one turn.
func (s *Scanner) StartApp(ctx context.Context, name string) error {
	if _, images := s.Snapshot(); !slices.ContainsFunc(images, func(image Image) bool { return image.uses(name) }) {
		return ErrNoApp
	}
	if !s.begin() {
		return ErrRunning
	}
	go s.run(ctx, name)

	return nil
}

// begin claims the one pass that may run.
func (s *Scanner) begin() bool {
	s.loaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return false
	}
	s.running = true

	return true
}

// run is a pass that begin has claimed: of every image, or of the images of the app only.
//
// A pass of one app keeps the inventory of the last full pass: one that took the containers
// listed now would have Follow miss the other apps installed meanwhile, whose images it does
// not scan. When the containers run other images than in that inventory, the pass scans
// everything instead, as Follow would. Only a full pass is the box's last run, and
// only a failure replaces the full pass's LastError: one app scanned fine says nothing of
// why the night stopped.
func (s *Scanner) run(ctx context.Context, only string) {
	s.mu.Lock()
	state := s.state
	state.Images, state.Told, state.ToldExploited = maps.Clone(s.state.Images), maps.Clone(s.state.Told), maps.Clone(s.state.ToldExploited)
	s.mu.Unlock()

	failed := ""
	fail := func(words string) {
		if failed == "" {
			failed = words
		}
	}

	if !s.waitWhileBusy(ctx) {
		fail("the box stayed busy")
	} else if tmp, err := s.emptyTmp(ctx); err != nil {
		fail(err.Error())
	} else if listed, err := s.Docker.Containers(ctx); err != nil {
		fail(err.Error())
	} else {
		if listed := GroupImages(listed); only == "" || !reflect.DeepEqual(listed, state.Inventory) {
			state.Inventory, only = listed, ""
		}
		s.scan(ctx, tmp, &state, only, fail)
		forget(&state)
		s.tell(ctx, &state)
	}

	if only == "" {
		state.LastRun, state.LastError = s.Now(), failed
	} else if failed != "" {
		state.LastError = failed
	}
	if err := state.Save(s.Dir); err != nil {
		logger.Error("the scan results cannot be kept", zap.String("dir", s.Dir), zap.Error(err))
		state.LastError = err.Error()
	}

	s.mu.Lock()
	s.state, s.running = state, false
	s.mu.Unlock()
}

// waitWhileBusy is false when the box stayed busy for BusyLimit, or ctx ended. A Busy that
// cannot tell counts as not busy: a scan only reads, at the lowest priority.
func (s *Scanner) waitWhileBusy(ctx context.Context) bool {
	wait, limit := s.BusyWait, s.BusyLimit
	if wait == 0 {
		wait = time.Minute
	}
	if limit == 0 {
		limit = 2 * time.Hour
	}

	for start := time.Now(); ; {
		if busy, err := s.Busy(ctx); err != nil || !busy {
			return true
		}
		if time.Since(start) >= limit {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(wait):
		}
	}
}

// emptyTmp is the temporary folder, there and empty. A Trivy that was killed (the service
// stopped, the power went) leaves its copy of an image behind, as large as the image: left
// there, they would fill the disk and every new image would be refused for lack of room.
func (s *Scanner) emptyTmp(ctx context.Context) (string, error) {
	tmp, err := s.TmpDir(ctx)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return "", err
	}
	// under the token: a scan on demand may be making its copy in there
	err = s.withTrivy(ctx, func() error {
		entries, err := os.ReadDir(tmp)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := os.RemoveAll(filepath.Join(tmp, entry.Name())); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return "", err
	}

	return tmp, nil
}

// scan scans the images of the inventory, or those of the app only when it is named.
func (s *Scanner) scan(ctx context.Context, tmp string, state *State, only string, fail func(string)) {
	for _, image := range state.Inventory {
		if only != "" && !image.uses(only) {
			continue
		}
		if ctx.Err() != nil {
			fail(ctx.Err().Error())
			return
		}

		previous, scanned := state.Images[image.ID]
		scanned = scanned && previous.Skipped == ""

		// only the first scan of an image copies it; a later one reads Trivy's cache
		if !scanned {
			need := uint64(max(image.Size, 0)) + roomMargin
			if db, err := s.Trivy.DBUpdatedAt(); err != nil || db.IsZero() {
				need += roomDatabase
			}
			if free, err := s.Free(tmp); err == nil && free < need {
				state.Images[image.ID] = ImageResult{Skipped: SkippedNoRoom}
				continue
			}
		}

		// the full scan of an image with JAR files fails after copying the whole image:
		// once it is known for that, only its system packages are asked for
		result, err := s.scanOne(ctx, image.ID, scanned && previous.OSOnly)
		switch {
		case err == nil:
			state.Images[image.ID] = result
		case scanned:
			// what the last good scan found stays, with its date: a box that cannot refresh
			// the database for a night does not lose what it knows
			fail(err.Error())
		default:
			fail(err.Error())
			state.Images[image.ID] = ImageResult{Skipped: SkippedFailed}
		}
	}
}

func (s *Scanner) scanOne(ctx context.Context, image string, osOnly bool) (ImageResult, error) {
	run := func(osOnly bool) (data []byte, err error) {
		err = s.withTrivy(ctx, func() (err error) { data, err = s.Trivy.Scan(ctx, image, osOnly); return })
		return data, err
	}
	data, err := run(osOnly)
	if err != nil && !osOnly && trivy.NeedsJavaDB([]byte(err.Error())) {
		osOnly = true
		data, err = run(true)
	}
	if err != nil {
		return ImageResult{}, err
	}

	findings, err := trivy.Parse(data)
	if err != nil {
		return ImageResult{}, errors.New("trivy's report cannot be read: " + err.Error())
	}
	db, _ := s.Trivy.DBUpdatedAt() // read after the scan: Trivy refreshes its database in it

	return ImageResult{ScannedAt: s.Now(), DB: db, Findings: findings, OSOnly: osOnly}, nil
}

// forget drops the images that are no longer on the box and what was told of apps that are
// gone, so that an app installed again is announced again.
func forget(state *State) {
	ids, apps := map[string]bool{}, map[string]bool{}
	for _, image := range state.Inventory {
		ids[image.ID] = true
		for _, name := range image.Apps {
			apps[name] = true
		}
	}
	maps.DeleteFunc(state.Images, func(id string, _ ImageResult) bool { return !ids[id] })
	gone := func(name string, _ []string) bool { return !apps[name] }
	maps.DeleteFunc(state.Told, gone)
	maps.DeleteFunc(state.ToldExploited, gone)
}

// lists is the lists of exploited vulnerabilities in use; nil when there are none.
func (s *Scanner) lists() *threat.Lists {
	if s.Threat == nil {
		return nil
	}
	return s.Threat()
}

// byApp is, by app, the ids of the vulnerabilities (critical or high) attackers exploit, and
// of the critical ones they are not known to exploit, sorted. A container that belongs to no
// app is not in them.
func byApp(images []Image, state State, lists *threat.Lists) (exploitedIDs, critical map[string][]string) {
	exploitedIDs, critical = map[string][]string{}, map[string][]string{}
	for _, image := range images {
		for _, finding := range state.Images[image.ID].Findings {
			to := critical
			if exploited(lists, finding.ID) {
				to = exploitedIDs
			} else if finding.Severity != trivy.Critical {
				continue
			}
			for _, name := range image.Apps {
				to[name] = append(to[name], finding.ID)
			}
		}
	}
	for _, ids := range []map[string][]string{exploitedIDs, critical} {
		for name := range ids {
			slices.Sort(ids[name])
			ids[name] = slices.Compact(ids[name])
		}
	}

	return exploitedIDs, critical
}

// tell publishes EventExploited, then EventFound, for the vulnerabilities each event has not
// told yet of the apps an update is offered for: there is something to do about those. When
// the updates cannot be read nothing is told and nothing is noted, and the next pass tries
// again.
func (s *Scanner) tell(ctx context.Context, state *State) {
	exploitedIDs, critical := byApp(state.Inventory, *state, s.lists())
	if len(exploitedIDs) == 0 && len(critical) == 0 {
		return
	}
	updates, err := s.Updates(ctx)
	if err != nil {
		logger.Info("the updates offered cannot be read, nothing is announced by this pass", zap.Error(err))
		return
	}

	s.announce(EventExploited, exploitedIDs, state.ToldExploited, updates)
	// told as exploited, the owner knows the stronger thing: a list that goes away (turned
	// off, not loaded yet) or drops the id does not tell it again as found
	for name, ids := range critical {
		critical[name] = slices.DeleteFunc(ids, func(id string) bool { return slices.Contains(state.ToldExploited[name], id) })
	}
	s.announce(EventFound, critical, state.Told, updates)
}

// announce publishes event once for the ids of byApp not in told, of the apps an update is
// offered for, and notes them in told once the bus took it.
func (s *Scanner) announce(event string, byApp, told map[string][]string, updates map[string]bool) {
	var names []string
	fresh := map[string][]string{}
	count := 0
	for name, ids := range byApp {
		if !updates[name] {
			continue
		}
		for _, id := range ids {
			if !slices.Contains(told[name], id) {
				fresh[name] = append(fresh[name], id)
			}
		}
		if len(fresh[name]) > 0 {
			names = append(names, name)
			count += len(fresh[name])
		}
	}
	if count == 0 {
		return
	}

	slices.Sort(names)
	if err := s.Publish(event, map[string]string{"apps": strings.Join(names, ", "), "count": strconv.Itoa(count)}); err != nil {
		// not noted as told: the next pass tells it
		logger.Error("the vulnerabilities found could not be announced", zap.String("event", event), zap.Error(err))
		return
	}
	for name, ids := range fresh {
		told[name] = append(told[name], ids...)
	}
}
