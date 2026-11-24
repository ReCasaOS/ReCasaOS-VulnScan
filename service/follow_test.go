package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// follow runs Follow on the rig, with a stream of Docker events the test feeds: each value
// sent on the returned channel is one container made.
func (r *rig) follow(t *testing.T) (made chan<- struct{}, stop func()) {
	t.Helper()
	events := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Follow(ctx, func(ctx context.Context, on func()) error {
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-events:
					on()
				}
			}
		})
	}()

	return events, func() { cancel(); <-done }
}

func (r *rig) setContainers(containers ...Container) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.containers = containers
}

func (r *rig) scanned() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.scans...)
}

// waitScans waits for the rig to have scanned n times and for the pass to be over.
func (r *rig) waitScans(t *testing.T, n int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); len(r.scanned()) < n || r.Running(); {
		if time.Now().After(deadline) {
			t.Fatalf("scans %v: want %d", r.scanned(), n)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// An app that was just updated runs a new image: the red badge must not wait for the night.
func TestFollowScansWhenAnAppRunsANewImage(t *testing.T) {
	r := newRig(t)
	r.setContainers(app("a", "sha256:1"))
	r.reports["sha256:1"], r.reports["sha256:2"] = report("CRITICAL CVE-1"), report()
	r.pass()
	made, stop := r.follow(t)
	defer stop()

	r.setContainers(app("a", "sha256:2"))
	made <- struct{}{}
	r.waitScans(t, 2)

	state, _ := r.Snapshot()
	if _, kept := state.Images["sha256:1"]; kept {
		t.Error("the image the app left is still in the results")
	}
	if _, there := state.Images["sha256:2"]; !there {
		t.Errorf("the new image is not in the results: %v", state.Images)
	}
}

// A container made again from the same image (a restart of the app, a change of its
// settings) and a container made by hand change nothing an app runs: no pass.
func TestFollowLeavesAloneWhatDidNotChange(t *testing.T) {
	r := newRig(t)
	r.setContainers(app("a", "sha256:1"))
	r.reports["sha256:1"] = report()
	r.pass()
	made, stop := r.follow(t)

	defer stop()
	r.reports["sha256:2"], r.reports["sha256:9"] = report(), report()

	made <- struct{}{}
	time.Sleep(30 * time.Millisecond)
	r.setContainers(app("a", "sha256:1"), Container{Name: "byhand", ImageID: "sha256:9", ImageSize: 10})
	made <- struct{}{}
	time.Sleep(30 * time.Millisecond)
	if scans := r.scanned(); len(scans) != 1 {
		t.Fatalf("scans %v: want the one of the pass by hand", scans)
	}

	// the stand-in still follows: a new image of the app is scanned
	r.setContainers(app("a", "sha256:2"), Container{Name: "byhand", ImageID: "sha256:9", ImageSize: 10})
	made <- struct{}{}
	r.waitScans(t, 3)
}

// A pass that runs may have listed the containers before the update made the new one: the
// change is not lost, it is scanned once that pass is over.
func TestFollowScansAChangeMadeDuringAPass(t *testing.T) {
	r := newRig(t)
	followRetry = 5 * time.Millisecond
	t.Cleanup(func() { followRetry = 10 * time.Second })
	r.setContainers(app("a", "sha256:1"))
	r.reports["sha256:1"], r.reports["sha256:2"] = report(), report()
	r.block = make(chan struct{})
	if !r.Start(context.Background()) {
		t.Fatal("the pass did not start")
	}
	time.Sleep(30 * time.Millisecond) // the pass has listed the containers and waits in its scan
	made, stop := r.follow(t)
	defer stop()

	r.setContainers(app("a", "sha256:2"))
	made <- struct{}{}
	time.Sleep(20 * time.Millisecond) // Follow finds the pass running
	close(r.block)
	r.waitScans(t, 2)

	if state, _ := r.Snapshot(); len(state.Inventory) != 1 || state.Inventory[0].ID != "sha256:2" {
		t.Fatalf("inventory %+v: want the new image", state.Inventory)
	}
}

// Docker restarts during the box's own update: the stream is asked again, and what changed
// meanwhile is found without an event.
func TestFollowAsksTheStreamAgainAndChecks(t *testing.T) {
	r := newRig(t)
	followRetry = 5 * time.Millisecond
	t.Cleanup(func() { followRetry = 10 * time.Second })
	r.setContainers(app("a", "sha256:1"))
	r.reports["sha256:1"], r.reports["sha256:2"] = report(), report()
	r.pass()
	r.setContainers(app("a", "sha256:2"))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	asked := make(chan struct{}, 100)
	go func() {
		defer close(done)
		r.Follow(ctx, func(context.Context, func()) error {
			asked <- struct{}{}
			return errors.New("docker is gone")
		})
	}()
	<-asked
	<-asked
	r.waitScans(t, 2)
	cancel()
	<-done
}

func TestDockerCreatedTellsEachContainerMade(t *testing.T) {
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Path + "?" + r.URL.Query().Get("filters")
		w.Write([]byte(`{"Type":"container","Action":"create"}` + "\n" + `{"Type":"container","Action":"create"}` + "\n"))
	}))
	defer server.Close()
	docker := NewDockerSocket("unused")
	docker.base, docker.stream = server.URL, server.Client()

	count := 0
	if err := docker.Created(context.Background(), func() { count++ }); err == nil {
		t.Error("a stream that ended is an error: the caller asks again")
	}
	if count != 2 {
		t.Errorf("told %d times, want 2", count)
	}
	if want := `/events?{"type":["container"],"event":["create"]}`; query != want {
		t.Errorf("asked %s, want %s", query, want)
	}
}
