package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// rig is a box made of stand-ins: its containers, what Trivy says of each image, the apps an
// update is offered for, and what was published.
type rig struct {
	t          *testing.T
	mu         sync.Mutex
	containers []Container
	dockerErr  error
	reports    map[string]string // image id -> report, or "!words" for a failure
	scans      []string          // "id" or "id os"
	db         time.Time
	updates    map[string]bool
	updatesErr error
	busy       []bool // one answer per question, then not busy
	free       uint64
	published  []map[string]string
	publishErr error
	tmpErr     error
	tmp        string
	now        time.Time
	block      chan struct{} // when set, a scan waits for it
	entered    chan struct{} // when set, a scan says it began
	*Scanner
}

func (r *rig) Containers(context.Context) ([]Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.containers, r.dockerErr
}
func (r *rig) RootDir(context.Context) (string, error) { return "/var/lib/docker", nil }
func (r *rig) DBUpdatedAt() (time.Time, error)         { return r.db, nil }

func (r *rig) Scan(_ context.Context, image string, osOnly bool) ([]byte, error) {
	if r.entered != nil {
		r.entered <- struct{}{}
	}
	if r.block != nil {
		<-r.block
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	call := image
	if osOnly {
		call += " os"
	}
	r.scans = append(r.scans, call)
	report, known := r.reports[call]
	if !known {
		report = r.reports[image]
	}
	if strings.HasPrefix(report, "!") {
		return nil, errors.New("trivy: exit status 1: " + report[1:])
	}

	return []byte(report), nil
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, reports: map[string]string{}, updates: map[string]bool{}, free: 1 << 40,
		db: time.Date(2026, 11, 23, 19, 0, 0, 0, time.UTC), now: time.Date(2026, 11, 24, 5, 30, 0, 0, time.UTC)}
	tmp := t.TempDir()
	r.tmp = tmp
	r.Scanner = &Scanner{
		Docker: r, Trivy: r, Dir: t.TempDir(),
		TmpDir: func(context.Context) (string, error) { return tmp, r.tmpErr },
		Busy: func(context.Context) (bool, error) {
			if len(r.busy) == 0 {
				return false, nil
			}
			answer := r.busy[0]
			r.busy = r.busy[1:]
			return answer, nil
		},
		Updates: func(context.Context) (map[string]bool, error) { return r.updates, r.updatesErr },
		Free:    func(string) (uint64, error) { return r.free, nil },
		Publish: func(name string, properties map[string]string) error {
			if name != EventFound {
				t.Errorf("published %q", name)
			}
			if r.publishErr != nil {
				return r.publishErr
			}
			r.published = append(r.published, properties)
			return nil
		},
		Now:      func() time.Time { return r.now },
		BusyWait: time.Millisecond, BusyLimit: time.Second,
	}

	return r
}

func (r *rig) pass() {
	r.t.Helper()
	if err := r.Pass(context.Background()); err != nil {
		r.t.Fatal(err)
	}
}

// report is a Trivy report with one vulnerability per "SEVERITY id" given.
func report(findings ...string) string {
	var vulnerabilities []string
	for _, f := range findings {
		severity, id, _ := strings.Cut(f, " ")
		vulnerabilities = append(vulnerabilities, fmt.Sprintf(`{"VulnerabilityID":%q,"PkgName":"pkg","InstalledVersion":"1","FixedVersion":"2","Severity":%q}`, id, severity))
	}

	return `{"Results":[{"Vulnerabilities":[` + strings.Join(vulnerabilities, ",") + `]}]}`
}

func app(name, image string) Container {
	return Container{Name: name + "-1", ImageID: image, Project: name, ImageSize: 1 << 30}
}

func TestPassScansEachImageOnce(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1"), app("a", "sha256:1"), app("b", "sha256:2")}
	r.reports["sha256:1"], r.reports["sha256:2"] = report("HIGH CVE-1"), report()
	r.pass()

	if !reflect.DeepEqual(r.scans, []string{"sha256:1", "sha256:2"}) {
		t.Fatalf("scans %v", r.scans)
	}
	state, images := r.Snapshot()
	if len(images) != 2 || len(state.Images["sha256:1"].Findings) != 1 || len(state.Images["sha256:2"].Findings) != 0 {
		t.Fatalf("%+v", state.Images)
	}
	if got := state.Images["sha256:1"]; !got.ScannedAt.Equal(r.now) || !got.DB.Equal(r.db) || got.Skipped != "" {
		t.Fatalf("%+v: want the time of the pass and the date of the database", got)
	}
	if !state.LastRun.Equal(r.now) || state.LastError != "" {
		t.Fatalf("last run %v, error %q", state.LastRun, state.LastError)
	}
	if kept := Load(r.Dir); !reflect.DeepEqual(kept.Images, state.Images) {
		t.Fatalf("what is on disk is not what is served: %+v", kept.Images)
	}
}

// A scan with a warm cache takes under a second and writes nothing (measured), and Trivy
// refreshes its database inside a scan: every pass scans every image.
func TestPassRescansEveryPass(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report()
	r.pass()
	r.reports["sha256:1"] = report("HIGH CVE-NEW")
	r.pass()

	if state, _ := r.Snapshot(); len(r.scans) != 2 || len(state.Images["sha256:1"].Findings) != 1 {
		t.Fatalf("scans %v, %+v", r.scans, state.Images)
	}
}

func TestPassNotEnoughRoom(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.free = 1<<30 + 1<<30 - 1 // the image and a GiB, less one byte
	r.pass()

	if state, _ := r.Snapshot(); len(r.scans) != 0 || state.Images["sha256:1"].Skipped != SkippedNoRoom {
		t.Fatalf("scans %v, %+v", r.scans, state.Images)
	}
}

// Only the first scan of an image copies it: one already scanned needs no room.
func TestPassRoomNotAskedForARescan(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report()
	r.pass()
	r.free = 0
	r.pass()

	if state, _ := r.Snapshot(); len(r.scans) != 2 || state.Images["sha256:1"].Skipped != "" {
		t.Fatalf("scans %v, %+v", r.scans, state.Images)
	}
}

func TestPassScanFailureContinues(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1"), app("b", "sha256:2")}
	r.reports["sha256:1"], r.reports["sha256:2"] = "!context deadline exceeded", report("HIGH CVE-1")
	r.pass()

	state, _ := r.Snapshot()
	if state.Images["sha256:1"].Skipped != SkippedFailed || len(state.Images["sha256:2"].Findings) != 1 {
		t.Fatalf("%+v", state.Images)
	}
	if !strings.Contains(state.LastError, "context deadline exceeded") {
		t.Fatalf("last error %q: want Trivy's words", state.LastError)
	}
}

func TestPassUnreadableReportIsAFailure(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = "{"
	r.pass()

	if state, _ := r.Snapshot(); state.Images["sha256:1"].Skipped != SkippedFailed {
		t.Fatalf("%+v", state.Images)
	}
}

// A box with no network cannot refresh the database and every scan fails: what the last
// good scan found stays, with its date.
func TestPassOfflineKeepsResults(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report("CRITICAL CVE-1")
	r.pass()
	before, _ := r.Snapshot()

	r.now = r.now.Add(24 * time.Hour)
	r.reports["sha256:1"] = "!failed to download vulnerability DB"
	r.pass()

	state, _ := r.Snapshot()
	if !reflect.DeepEqual(state.Images, before.Images) {
		t.Fatalf("%+v\nwant what the last good scan found: %+v", state.Images, before.Images)
	}
	if !strings.Contains(state.LastError, "failed to download vulnerability DB") || !state.LastRun.Equal(r.now) {
		t.Fatalf("last error %q at %v", state.LastError, state.LastRun)
	}
}

func TestPassDockerDownKeepsState(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report("CRITICAL CVE-1")
	r.updates["a"] = true
	r.pass()
	before, imagesBefore := r.Snapshot()

	r.dockerErr = errors.New("Cannot connect to the Docker daemon")
	r.pass()

	state, images := r.Snapshot()
	if !reflect.DeepEqual(state.Images, before.Images) || !reflect.DeepEqual(state.Told, before.Told) || !reflect.DeepEqual(images, imagesBefore) {
		t.Fatalf("%+v %+v", state, images)
	}
	if !strings.Contains(state.LastError, "Cannot connect") {
		t.Fatalf("last error %q", state.LastError)
	}
}

func TestPassSharedImageBothApps(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("b", "sha256:1"), app("a", "sha256:1")}
	r.reports["sha256:1"] = report("CRITICAL CVE-1")
	r.updates["a"], r.updates["b"] = true, true
	r.pass()

	want := []map[string]string{{"apps": "a, b", "count": "2"}}
	if !reflect.DeepEqual(r.published, want) {
		t.Fatalf("published %v, want %v", r.published, want)
	}
}

func TestPassTellsOnce(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report("CRITICAL CVE-1", "CRITICAL CVE-2")
	r.updates["a"] = true
	r.pass()
	r.pass()

	want := []map[string]string{{"apps": "a", "count": "2"}}
	if !reflect.DeepEqual(r.published, want) {
		t.Fatalf("published %v, want %v", r.published, want)
	}
}

func TestPassTellsNewCritical(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report("CRITICAL CVE-1")
	r.updates["a"] = true
	r.pass()
	r.reports["sha256:1"] = report("CRITICAL CVE-1", "CRITICAL CVE-2")
	r.pass()

	if len(r.published) != 2 || r.published[1]["count"] != "1" {
		t.Fatalf("published %v", r.published)
	}
}

// What was told survives a restart of the service.
func TestPassToldIsKept(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report("CRITICAL CVE-1")
	r.updates["a"] = true
	r.pass()

	again := newRig(t)
	again.Dir = r.Dir
	again.containers, again.reports, again.updates = r.containers, r.reports, r.updates
	again.pass()
	if len(again.published) != 0 {
		t.Fatalf("told again after a restart: %v", again.published)
	}
}

func TestPassHighOnlyTellsNothing(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report("HIGH CVE-1")
	r.updates["a"] = true
	r.pass()

	if len(r.published) != 0 {
		t.Fatalf("published %v", r.published)
	}
}

func TestPassCriticalWithoutUpdateTellsNothing(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report("CRITICAL CVE-1")
	r.pass()

	if state, _ := r.Snapshot(); len(r.published) != 0 || len(state.Told["a"]) != 0 {
		t.Fatalf("published %v, told %v", r.published, state.Told)
	}
}

func TestPassTellsWhenUpdateAppears(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report("CRITICAL CVE-1")
	r.pass()
	r.updates["a"] = true
	r.pass()

	want := []map[string]string{{"apps": "a", "count": "1"}}
	if !reflect.DeepEqual(r.published, want) {
		t.Fatalf("published %v, want %v", r.published, want)
	}
}

func TestPassUpdatesUnknownTellsNothing(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report("CRITICAL CVE-1")
	r.updates["a"], r.updatesErr = true, errors.New("app-management does not answer")
	r.pass()

	state, _ := r.Snapshot()
	if len(r.published) != 0 || len(state.Told) != 0 || state.LastError != "" {
		t.Fatalf("published %v, told %v, last error %q", r.published, state.Told, state.LastError)
	}
}

// A container made by hand has no update to offer: it is never announced.
func TestPassLooseContainerTellsNothing(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{{Name: "byhand", ImageID: "sha256:1", ImageSize: 1}}
	r.reports["sha256:1"] = report("CRITICAL CVE-1")
	r.updates["byhand"] = true
	r.pass()

	if len(r.published) != 0 {
		t.Fatalf("published %v", r.published)
	}
}

func TestPassJavaFallback(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = "!Unable to initialize the Java DB: Java DB update failed"
	r.reports["sha256:1 os"] = report("HIGH CVE-1")
	r.pass()

	state, _ := r.Snapshot()
	got := state.Images["sha256:1"]
	if !reflect.DeepEqual(r.scans, []string{"sha256:1", "sha256:1 os"}) || !got.OSOnly || got.Skipped != "" || len(got.Findings) != 1 || state.LastError != "" {
		t.Fatalf("scans %v, %+v, last error %q", r.scans, got, state.LastError)
	}
}

func TestPassWaitsWhileBusy(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.busy = []bool{true, true, false}
	r.pass()

	if len(r.busy) != 0 || len(r.scans) != 1 {
		t.Fatalf("%d answers left, scans %v", len(r.busy), r.scans)
	}
}

func TestPassGivesUpWhenBusyTooLong(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.Busy = func(context.Context) (bool, error) { return true, nil }
	r.BusyLimit = 5 * time.Millisecond
	r.pass()

	if state, _ := r.Snapshot(); len(r.scans) != 0 || state.LastError != "the box stayed busy" {
		t.Fatalf("scans %v, last error %q", r.scans, state.LastError)
	}
}

func TestPassBusyUnknownScans(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.Busy = func(context.Context) (bool, error) { return false, errors.New("app-management does not answer") }
	r.pass()

	if len(r.scans) != 1 {
		t.Fatalf("scans %v", r.scans)
	}
}

func TestPassAlreadyRunning(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.block = make(chan struct{})
	done := make(chan error)
	go func() { done <- r.Pass(context.Background()) }()
	for !r.Running() {
		time.Sleep(time.Millisecond)
	}

	if err := r.Pass(context.Background()); !errors.Is(err, ErrRunning) {
		t.Fatalf("err %v, want ErrRunning", err)
	}
	close(r.block)
	if err := <-done; err != nil || r.Running() {
		t.Fatalf("err %v, running %v", err, r.Running())
	}
}

func TestPassForgetsRemovedApps(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1"), app("b", "sha256:2")}
	r.reports["sha256:1"], r.reports["sha256:2"] = report("CRITICAL CVE-1"), report("CRITICAL CVE-2")
	r.updates["a"], r.updates["b"] = true, true
	r.pass()
	r.containers = r.containers[:1]
	r.pass()

	state, images := r.Snapshot()
	if _, kept := state.Images["sha256:2"]; kept || len(state.Told["b"]) != 0 || len(images) != 1 {
		t.Fatalf("%+v %+v", state, images)
	}
	if len(state.Told["a"]) != 1 {
		t.Fatalf("told %v: the app that stays keeps what it was told", state.Told)
	}
}

// What is served after a restart is what was served before it: the images are kept with
// their results, not learnt again at the next night.
func TestSnapshotAfterARestart(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report("CRITICAL CVE-1")
	r.pass()
	_, before := r.Snapshot()

	again := newRig(t)
	again.Dir = r.Dir
	if _, images := again.Snapshot(); len(images) != 1 || !reflect.DeepEqual(images, before) {
		t.Fatalf("%+v, want %+v", images, before)
	}

	// and a first pass that finds Docker down leaves them
	again.dockerErr = errors.New("Cannot connect to the Docker daemon")
	again.pass()
	if state, images := again.Snapshot(); len(images) != 1 || len(state.Images["sha256:1"].Findings) != 1 {
		t.Fatalf("%+v %+v", state.Images, images)
	}
}

// A Trivy that was killed (a stop of the service, a power cut) leaves its copy of the image
// behind: the next pass starts from an empty folder.
func TestPassEmptiesTheTemporaryFolder(t *testing.T) {
	r := newRig(t)
	left := filepath.Join(r.tmp, "fanal-123", "layer.tar")
	if err := os.MkdirAll(filepath.Dir(left), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(left, []byte("3.5 GB of image"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.pass()

	if entries, err := os.ReadDir(r.tmp); err != nil || len(entries) != 0 {
		t.Fatalf("%v, err %v: want the folder there and empty", entries, err)
	}
}

// No folder to work in (Docker does not say where its data is): nothing is scanned, and
// nothing is written anywhere else.
func TestPassWithoutAWorkFolder(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.tmpErr = errors.New("docker does not say where its data is")
	r.pass()

	if state, _ := r.Snapshot(); len(r.scans) != 0 || state.LastError != "docker does not say where its data is" {
		t.Fatalf("scans %v, last error %q", r.scans, state.LastError)
	}
}

// The first scan of a box downloads the database too, 1.7 GB of it.
func TestPassRoomForTheDatabase(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.free = 1<<30 + 1<<30 + 1<<30 // the image, the margin, and not the database
	r.db = time.Time{}
	r.pass()
	if state, _ := r.Snapshot(); len(r.scans) != 0 || state.Images["sha256:1"].Skipped != SkippedNoRoom {
		t.Fatalf("no database yet: scans %v, %+v", r.scans, state.Images)
	}

	r.db = time.Date(2026, 11, 23, 19, 0, 0, 0, time.UTC)
	r.pass()
	if len(r.scans) != 1 {
		t.Fatalf("the database is there: scans %v", r.scans)
	}
}

// An alert the bus did not take is not noted as told: the next pass tells it.
func TestPassToldOnlyOncePublished(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report("CRITICAL CVE-1")
	r.updates["a"] = true
	r.publishErr = errors.New("the message bus does not answer")
	r.pass()
	if state, _ := r.Snapshot(); len(state.Told) != 0 {
		t.Fatalf("told %v although nothing was published", state.Told)
	}

	r.publishErr = nil
	r.pass()
	if want := []map[string]string{{"apps": "a", "count": "1"}}; !reflect.DeepEqual(r.published, want) {
		t.Fatalf("published %v, want %v", r.published, want)
	}
}

// The full scan of an image with JAR files fails after it copied the whole image: once the
// image is known for it, only its system packages are asked for.
func TestPassJavaImageIsNotTriedInFullAgain(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = "!Unable to initialize the Java DB: Java DB update failed"
	r.reports["sha256:1 os"] = report()
	r.pass()
	r.pass()

	if want := []string{"sha256:1", "sha256:1 os", "sha256:1 os"}; !reflect.DeepEqual(r.scans, want) {
		t.Fatalf("scans %v, want %v", r.scans, want)
	}
	if state, _ := r.Snapshot(); !state.Images["sha256:1"].OSOnly {
		t.Fatal("the image is no longer said to be scanned for its system packages only")
	}
}
