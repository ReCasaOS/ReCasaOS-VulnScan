package service

import (
	"context"
	"testing"
	"time"
)

func TestNextRunBefore(t *testing.T) {
	got := NextRun(time.Date(2026, 11, 24, 3, 0, 0, 0, time.UTC))
	if want := time.Date(2026, 11, 24, 5, 30, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("%v, want %v", got, want)
	}
}

func TestNextRunAfter(t *testing.T) {
	want := time.Date(2026, 11, 25, 5, 30, 0, 0, time.UTC)
	for _, now := range []time.Time{
		time.Date(2026, 11, 24, 5, 30, 0, 0, time.UTC), // on the dot: tonight's is this one, the next is tomorrow's
		time.Date(2026, 11, 24, 18, 0, 0, 0, time.UTC),
	} {
		if got := NextRun(now); !got.Equal(want) {
			t.Errorf("%v: %v, want %v", now, got, want)
		}
	}
}

// The night the clocks change has 23 or 25 hours: the scan is at 05:30 on the box's clock.
func TestNextRunDST(t *testing.T) {
	paris, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Skip("no time zone database here")
	}
	for _, day := range []time.Time{
		time.Date(2026, 3, 28, 18, 0, 0, 0, paris),  // the clocks go forward on the 29th
		time.Date(2026, 10, 24, 18, 0, 0, 0, paris), // and back on the 25th
	} {
		got := NextRun(day)
		if got.Hour() != 5 || got.Minute() != 30 || got.Day() != day.Day()+1 || got.Location() != paris {
			t.Errorf("%v: %v, want 05:30 the next day in Paris", day, got)
		}
	}
}

// A box that has just had the module installed has nothing to show until 05:30: the first
// pass does not wait for the night.
func TestRunNightlyScansAtOnceWhenNeverScanned(t *testing.T) {
	r := newRig(t)
	r.now = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.RunNightly(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if state, _ := r.Snapshot(); !state.LastRun.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no pass before the night")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

// A restart of a box that has its results does not scan again: the night does.
func TestRunNightlyWaitsForTheNightOnceScanned(t *testing.T) {
	r := newRig(t)
	r.now = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report()
	r.pass()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.RunNightly(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.scans) != 1 {
		t.Fatalf("scans %v: want the one of the pass by hand", r.scans)
	}
}
