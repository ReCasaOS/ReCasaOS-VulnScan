package service

import (
	"context"
	"errors"
	"maps"
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

// roomMargin is what must stay free beside the copy of the image Trivy makes.
const roomMargin = 1 << 30

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
	Free    func(dir string) (uint64, error)
	Publish func(name string, properties map[string]string)
	Now     func() time.Time
	// Dir keeps the results; Tmp is where Trivy copies an image the first time it scans it.
	Dir, Tmp string
	// BusyWait is the time between two questions to Busy, and BusyLimit when the pass gives
	// up. Zero is a minute and two hours.
	BusyWait, BusyLimit time.Duration

	load    sync.Once
	mu      sync.Mutex // guards what follows
	running bool
	state   State
	images  []Image
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

	return state, slices.Clone(s.images)
}

// Pass scans every image once. It returns ErrRunning when a pass runs already, and nil
// otherwise: what went wrong is kept as the state's LastError, beside the results.
func (s *Scanner) Pass(ctx context.Context) error {
	s.loaded()
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return ErrRunning
	}
	s.running = true
	state := s.state
	state.Images, state.Told = maps.Clone(s.state.Images), maps.Clone(s.state.Told)
	images := s.images
	s.mu.Unlock()

	state.LastError = ""
	fail := func(words string) {
		if state.LastError == "" {
			state.LastError = words
		}
	}

	if s.waitWhileBusy(ctx) {
		if listed, err := s.Docker.Containers(ctx); err != nil {
			fail(err.Error())
		} else {
			images = GroupImages(listed)
			s.scan(ctx, images, &state, fail)
			forget(images, &state)
			s.tell(ctx, images, &state)
		}
	} else {
		fail("the box stayed busy")
	}

	state.LastRun = s.Now()
	if err := state.Save(s.Dir); err != nil {
		logger.Error("the scan results cannot be kept", zap.String("dir", s.Dir), zap.Error(err))
		fail(err.Error())
	}

	s.mu.Lock()
	s.state, s.images, s.running = state, images, false
	s.mu.Unlock()

	return nil
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

func (s *Scanner) scan(ctx context.Context, images []Image, state *State, fail func(string)) {
	for _, image := range images {
		if ctx.Err() != nil {
			fail(ctx.Err().Error())
			return
		}

		previous, scanned := state.Images[image.ID]
		scanned = scanned && previous.Skipped == ""

		// only the first scan of an image copies it; a later one reads Trivy's cache
		if !scanned {
			if free, err := s.Free(s.Tmp); err == nil && free < uint64(max(image.Size, 0))+roomMargin {
				state.Images[image.ID] = ImageResult{Skipped: SkippedNoRoom}
				continue
			}
		}

		result, err := s.scanOne(ctx, image.ID)
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

func (s *Scanner) scanOne(ctx context.Context, image string) (ImageResult, error) {
	osOnly := false
	data, err := s.Trivy.Scan(ctx, image, false)
	if err != nil && trivy.NeedsJavaDB([]byte(err.Error())) {
		osOnly = true
		data, err = s.Trivy.Scan(ctx, image, true)
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
func forget(images []Image, state *State) {
	ids, apps := map[string]bool{}, map[string]bool{}
	for _, image := range images {
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
func (s *Scanner) tell(ctx context.Context, images []Image, state *State) {
	critical := criticalByApp(images, *state)
	if len(critical) == 0 {
		return
	}
	updates, err := s.Updates(ctx)
	if err != nil {
		logger.Info("the updates offered cannot be read, nothing is announced by this pass", zap.Error(err))
		return
	}

	var names []string
	count := 0
	for name, ids := range critical {
		if !updates[name] {
			continue
		}
		fresh := 0
		for _, id := range ids {
			if !slices.Contains(state.Told[name], id) {
				state.Told[name] = append(state.Told[name], id)
				fresh++
			}
		}
		if fresh > 0 {
			names = append(names, name)
			count += fresh
		}
	}
	if count == 0 {
		return
	}

	slices.Sort(names)
	s.Publish(EventFound, map[string]string{"apps": strings.Join(names, ", "), "count": strconv.Itoa(count)})
}
