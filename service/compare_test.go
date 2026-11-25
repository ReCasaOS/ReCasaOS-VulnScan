package service

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/trivy"
)

func ids(findings []trivy.Finding) []string {
	var out []string
	for _, f := range findings {
		out = append(out, f.ID)
	}

	return out
}

func TestCompareWorse(t *testing.T) {
	r := newRig(t)
	r.reports["cur"], r.reports["cand"] = report("CRITICAL CVE-1"), report("CRITICAL CVE-1", "CRITICAL CVE-3", "CRITICAL CVE-2")
	got := r.Compare(context.Background(), "cur", "cand")

	if got.Verdict != VerdictWorse || got.CurrentCritical != 1 || got.CandidateCritical != 3 || !reflect.DeepEqual(ids(got.Added), []string{"CVE-2", "CVE-3"}) {
		t.Fatalf("%+v", got)
	}
}

func TestCompareFewerIsNotWorse(t *testing.T) {
	r := newRig(t)
	r.reports["cur"], r.reports["cand"] = report("CRITICAL CVE-1", "CRITICAL CVE-2", "CRITICAL CVE-3"), report("CRITICAL CVE-1")
	got := r.Compare(context.Background(), "cur", "cand")

	if got.Verdict != VerdictNotWorse || got.CurrentCritical != 3 || got.CandidateCritical != 1 || len(got.Added) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestCompareSameCountOtherIDsIsNotWorse(t *testing.T) {
	r := newRig(t)
	r.reports["cur"], r.reports["cand"] = report("CRITICAL CVE-1", "CRITICAL CVE-2"), report("CRITICAL CVE-4", "CRITICAL CVE-3")
	got := r.Compare(context.Background(), "cur", "cand")

	if got.Verdict != VerdictNotWorse || !reflect.DeepEqual(ids(got.Added), []string{"CVE-3", "CVE-4"}) {
		t.Fatalf("%+v", got)
	}
}

func TestCompareHighDoesNotCount(t *testing.T) {
	r := newRig(t)
	r.reports["cur"] = report("CRITICAL CVE-1")
	r.reports["cand"] = report("CRITICAL CVE-1", "HIGH H-1", "HIGH H-2", "HIGH H-3", "HIGH H-4", "HIGH H-5")
	got := r.Compare(context.Background(), "cur", "cand")

	if got.Verdict != VerdictNotWorse || got.CandidateCritical != 1 || len(got.Added) != 0 {
		t.Fatalf("%+v", got)
	}
}

// Both are compared in the same mode, or the one with the JAR files would count more.
func TestCompareSameMode(t *testing.T) {
	r := newRig(t)
	r.reports["cand"] = "!Unable to initialize the Java DB: Java DB update failed"
	r.reports["cand os"], r.reports["cur os"] = report(), report("CRITICAL CVE-1")
	got := r.Compare(context.Background(), "cur", "cand")

	if !reflect.DeepEqual(r.scans, []string{"cand", "cand os", "cur os"}) || got.Verdict != VerdictNotWorse {
		t.Fatalf("scans %v, %+v", r.scans, got)
	}
}

// The current one can fall back where the candidate did not: the candidate is scanned again.
func TestCompareCurrentFallsBack(t *testing.T) {
	r := newRig(t)
	r.reports["cur"] = "!Unable to initialize the Java DB: Java DB update failed"
	r.reports["cur os"], r.reports["cand os"] = report(), report("CRITICAL CVE-1")
	r.reports["cand"] = report("CRITICAL CVE-1", "CRITICAL CVE-2")
	got := r.Compare(context.Background(), "cur", "cand")

	if !reflect.DeepEqual(r.scans, []string{"cand", "cur", "cur os", "cand os"}) || got.CandidateCritical != 1 {
		t.Fatalf("scans %v, %+v", r.scans, got)
	}
}

func TestCompareUnknownOnFailure(t *testing.T) {
	r := newRig(t)
	r.reports["cur"], r.reports["cand"] = report(), "!boom"
	got := r.Compare(context.Background(), "cur", "cand")

	if got.Verdict != VerdictUnknown || !strings.Contains(got.Reason, "boom") {
		t.Fatalf("%+v", got)
	}
}

func TestCompareUnknownWithoutRoom(t *testing.T) {
	r := newRig(t)
	r.free = 1<<30 + 1<<30 - 1
	got := r.Compare(context.Background(), "cur", "cand")

	if got.Verdict != VerdictUnknown || got.Reason != SkippedNoRoom || len(r.scans) != 0 {
		t.Fatalf("scans %v, %+v", r.scans, got)
	}
}

func TestCompareUnknownWithoutSize(t *testing.T) {
	r := newRig(t)
	r.sizeErr = os.ErrNotExist
	got := r.Compare(context.Background(), "cur", "cand")

	if got.Verdict != VerdictUnknown || !strings.Contains(got.Reason, os.ErrNotExist.Error()) || len(r.scans) != 0 {
		t.Fatalf("scans %v, %+v", r.scans, got)
	}
}

func TestCompareNothingToCompare(t *testing.T) {
	r := newRig(t)
	if got := r.Compare(context.Background(), "same", "same"); got.Verdict != VerdictNotWorse || got.CurrentCritical != 0 || got.CandidateCritical != 0 {
		t.Fatalf("%+v", got)
	}
	for _, pair := range [][2]string{{"", "cand"}, {"cur", ""}, {"", ""}} {
		if got := r.Compare(context.Background(), pair[0], pair[1]); got.Verdict != VerdictUnknown || got.Reason == "" {
			t.Fatalf("%q: %+v", pair, got)
		}
	}
	if len(r.scans) != 0 {
		t.Fatalf("scans %v", r.scans)
	}
}

func TestCompareLeavesStateAlone(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report("CRITICAL CVE-9")
	r.pass()
	beforeState, beforeImages := r.Snapshot()
	file := filepath.Join(r.Dir, "state.json")
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	r.reports["cur"], r.reports["cand"] = report("CRITICAL CVE-1"), report("CRITICAL CVE-2")
	r.now = r.now.Add(time.Hour)
	r.Compare(context.Background(), "cur", "cand")

	state, images := r.Snapshot()
	after, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state, beforeState) || !reflect.DeepEqual(images, beforeImages) || string(after) != string(before) {
		t.Fatalf("%+v\nwant %+v", state, beforeState)
	}
}

func TestCompareWritesNoStateFile(t *testing.T) {
	r := newRig(t)
	r.Compare(context.Background(), "cur", "cand")

	if _, err := os.Stat(filepath.Join(r.Dir, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("state.json written: %v", err)
	}
}

func TestCompareCancelledEmptiesTmpAndFreesTrivy(t *testing.T) {
	r := newRig(t)
	if err := os.WriteFile(filepath.Join(r.tmp, "copy-of-an-image"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.block, r.entered = make(chan struct{}), make(chan struct{}, 2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Comparison)
	go func() { done <- r.Compare(ctx, "cur", "cand") }()
	<-r.entered // the scan of the candidate waits
	cancel()
	got := <-done

	if got.Verdict != VerdictUnknown || got.Reason == "" {
		t.Fatalf("%+v", got)
	}
	if entries, _ := os.ReadDir(r.tmp); len(entries) != 0 {
		t.Fatalf("%d files left in the temporary folder", len(entries))
	}
	ran := false
	if err := r.withTrivy(context.Background(), func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("the token was not given back: %v", err)
	}
}
