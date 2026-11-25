package service

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/trivy"
	"go.uber.org/zap"
)

// EventFound is published once at the end of a pass that found a critical vulnerability not
// told yet in an app an update is offered for. Its properties: "apps", the names joined by
// ", ", and "count", how many such vulnerabilities there are in all.
const EventFound = "vuln:found"

var ErrRunning = errors.New("a scan is already running")

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
	state.Images, state.Told = maps.Clone(s.state.Images), maps.Clone(s.state.Told)

	return state, slices.Clone(s.state.Inventory)
}

// Pass scans every image once. It returns ErrRunning when a pass runs already, and nil
// otherwise: what went wrong is kept as the state's LastError, beside the results.
func (s *Scanner) Pass(ctx context.Context) error {
	if !s.begin() {
		return ErrRunning
	}
	s.run(ctx)

	return nil
}

// Start runs a pass in the background; false when one runs already.
func (s *Scanner) Start(ctx context.Context) bool {
	if !s.begin() {
		return false
	}
	go s.run(ctx)

	return true
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

// run is a pass that begin has claimed.
func (s *Scanner) run(ctx context.Context) {
	s.mu.Lock()
	state := s.state
	state.Images, state.Told = maps.Clone(s.state.Images), maps.Clone(s.state.Told)
	s.mu.Unlock()

	state.LastError = ""
	fail := func(words string) {
		if state.LastError == "" {
			state.LastError = words
		}
	}

	if !s.waitWhileBusy(ctx) {
		fail("the box stayed busy")
	} else if tmp, err := s.emptyTmp(ctx); err != nil {
		fail(err.Error())
	} else if listed, err := s.Docker.Containers(ctx); err != nil {
		fail(err.Error())
	} else {
		state.Inventory = GroupImages(listed)
		s.scan(ctx, tmp, &state, fail)
		forget(&state)
		s.tell(ctx, &state)
	}

	state.LastRun = s.Now()
	if err := state.Save(s.Dir); err != nil {
		logger.Error("the scan results cannot be kept", zap.String("dir", s.Dir), zap.Error(err))
		fail(err.Error())
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

func (s *Scanner) scan(ctx context.Context, tmp string, state *State, fail func(string)) {
	for _, image := range state.Inventory {
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
	maps.DeleteFunc(state.Told, func(name string, _ []string) bool { return !apps[name] })
}

// criticalByApp is the ids of the critical vulnerabilities of each app, sorted. A container
// that belongs to no app is not in it.
func criticalByApp(images []Image, state State) map[string][]string {
	critical := map[string][]string{}
	for _, image := range images {
		for _, finding := range state.Images[image.ID].Findings {
			if finding.Severity != trivy.Critical {
				continue
			}
			for _, name := range image.Apps {
				critical[name] = append(critical[name], finding.ID)
			}
		}
	}
	for name, ids := range critical {
		slices.Sort(ids)
		critical[name] = slices.Compact(ids)
	}

	return critical
}

// tell publishes EventFound for the critical vulnerabilities not told yet of the apps an
// update is offered for: there is something to do about those. When the updates cannot be
// read nothing is told and nothing is noted, and the next pass tries again.
func (s *Scanner) tell(ctx context.Context, state *State) {
	critical := criticalByApp(state.Inventory, *state)
	if len(critical) == 0 {
		return
	}
	updates, err := s.Updates(ctx)
	if err != nil {
		logger.Info("the updates offered cannot be read, nothing is announced by this pass", zap.Error(err))
		return
	}

	var names []string
	fresh := map[string][]string{}
	count := 0
	for name, ids := range critical {
		if !updates[name] {
			continue
		}
		for _, id := range ids {
			if !slices.Contains(state.Told[name], id) {
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
	if err := s.Publish(EventFound, map[string]string{"apps": strings.Join(names, ", "), "count": strconv.Itoa(count)}); err != nil {
		// not noted as told: the next pass tells it
		logger.Error("the vulnerabilities found could not be announced", zap.Error(err))
		return
	}
	for name, ids := range fresh {
		state.Told[name] = append(state.Told[name], ids...)
	}
}
