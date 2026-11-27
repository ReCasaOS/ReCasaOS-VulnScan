package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func newAPI(r *rig) *API {
	return &API{Scanner: r.Scanner, DB: r.DBUpdatedAt, Ctx: context.Background()}
}

func TestAPIStatusBeforeAnyScan(t *testing.T) {
	r := newRig(t)
	r.db = time.Time{}

	status := newAPI(r).Status()
	if status.Running || status.LastRun != nil || status.DbUpdatedAt != nil || status.LastError != "" {
		t.Fatalf("%+v: want nothing but running=false", status)
	}
}

func TestAPIStatusAfterAScan(t *testing.T) {
	r := newRig(t)
	r.dockerErr = errors.New("Cannot connect to the Docker daemon")
	r.pass()

	status := newAPI(r).Status()
	if status.Running || status.LastRun == nil || !status.LastRun.Equal(r.now) || status.DbUpdatedAt == nil || !status.DbUpdatedAt.Equal(r.db) || status.LastError != "Cannot connect to the Docker daemon" {
		t.Fatalf("%+v", status)
	}
}

func TestAPIStart(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.block = make(chan struct{})
	api := newAPI(r)

	if !api.Start() {
		t.Fatal("the first start is refused")
	}
	if !api.Status().Running {
		t.Fatal("not running right after a start")
	}
	if api.Start() {
		t.Fatal("a second start is accepted while the first runs")
	}
	close(r.block)
	for deadline := time.Now().Add(5 * time.Second); r.Running(); {
		if time.Now().After(deadline) {
			t.Fatal("the scan never ends")
		}
		time.Sleep(time.Millisecond)
	}
	if len(r.scans) != 1 {
		t.Fatalf("scans %v", r.scans)
	}
}

func TestAPIAppsAndApp(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1"), app("b", "sha256:2")}
	r.reports["sha256:1"], r.reports["sha256:2"] = report("CRITICAL CVE-1", "HIGH CVE-2"), report()
	r.updates["a"] = true
	r.pass()
	api := newAPI(r)

	apps := api.Apps()
	if len(apps) != 2 || apps[0].App != "a" || apps[0].Critical != 1 || apps[0].High != 1 || !apps[0].Actionable || apps[1].Actionable || apps[0].ScannedAt == nil {
		t.Fatalf("%+v", apps)
	}

	detail, found := api.App("a")
	if !found || len(detail.Images) != 1 || detail.Images[0].ImageId != "sha256:1" || len(detail.Images[0].Findings) != 2 || detail.Images[0].Findings[0].Id != "CVE-1" || detail.Images[0].Findings[0].Severity != "CRITICAL" {
		t.Fatalf("%+v %v", detail, found)
	}
	if _, found := api.App("nothing"); found {
		t.Fatal("an app that is not on the box is found")
	}
	// an image with no finding is an empty list, not null: the dashboard reads its length
	if detail, _ := api.App("b"); detail.Images[0].Findings == nil {
		t.Fatal("findings is null")
	}
}

// The grid of app-management is read at most every five minutes, and an answer that cannot
// be had lights no badge.
func TestAPIUpdatesAreKeptFiveMinutes(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report("CRITICAL CVE-1")
	r.pass()

	asked := 0
	r.Scanner.Updates = func(context.Context) (map[string]bool, error) {
		asked++
		if asked == 3 {
			return nil, errors.New("app-management does not answer")
		}
		return map[string]bool{"a": true}, nil
	}
	api := newAPI(r)

	if !api.Apps()[0].Actionable || !api.Apps()[0].Actionable || asked != 1 {
		t.Fatalf("asked %d times in a row, want once", asked)
	}
	r.now = r.now.Add(5*time.Minute + time.Second)
	if !api.Apps()[0].Actionable || asked != 2 {
		t.Fatalf("asked %d times after five minutes, want twice", asked)
	}
	r.now = r.now.Add(5*time.Minute + time.Second)
	if api.Apps()[0].Actionable {
		t.Fatal("a badge although app-management does not answer")
	}
}

func TestAPICompareSpeaksTheAPIsWords(t *testing.T) {
	r := newRig(t)
	r.reports["cur"], r.reports["cand"] = report("CRITICAL CVE-1"), report("CRITICAL CVE-1", "CRITICAL CVE-2")

	got := newAPI(r).Compare(context.Background(), "cur", "cand")
	if got.Verdict != "worse" || got.CurrentCritical != 1 || got.CandidateCritical != 2 || len(got.Added) != 1 || got.Added[0].Id != "CVE-2" || got.Added[0].Severity != "CRITICAL" {
		t.Fatalf("%+v", got)
	}
	// no finding is an empty list, not null: the caller reads its length
	if got := newAPI(r).Compare(context.Background(), "cand", "cur"); got.Verdict != "not_worse" || got.Added == nil {
		t.Fatalf("%+v", got)
	}
}

// exploited and epss are read from the lists in use; an unknown score is absent, not 0.
func TestAPIFindingCarriesExploitedAndEPSS(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1")}
	r.reports["sha256:1"] = report("HIGH CVE-2024-0001", "CRITICAL CVE-2024-0002")
	r.updates["a"] = true
	r.pass()
	r.lists = kevLists([]string{"CVE-2024-0001"}, map[string]float32{"CVE-2024-0001": 0.5})
	api := newAPI(r)

	detail, _ := api.App("a")
	data, err := json.Marshal(detail.Images[0].Findings)
	if err != nil {
		t.Fatal(err)
	}
	var list []map[string]any
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatal(err)
	}
	byID := map[string]map[string]any{}
	for _, f := range list {
		byID[f["id"].(string)] = f
	}
	high, critical := byID["CVE-2024-0001"], byID["CVE-2024-0002"]
	if len(list) != 2 || high["exploited"] != true || high["epss"] != 0.5 || critical["exploited"] != false {
		t.Fatalf("%s", data)
	}
	if _, there := critical["epss"]; there {
		t.Fatalf("%s: epss of an unknown score", data)
	}

	apps := api.Apps()
	if len(apps) != 1 || apps[0].Exploited != 1 || apps[0].EpssMax == nil || *apps[0].EpssMax != 0.5 || !apps[0].Actionable {
		t.Fatalf("%+v", apps)
	}
	r.lists = nil
	if data, _ := json.Marshal(api.Apps()); !strings.Contains(string(data), `"exploited":0`) || strings.Contains(string(data), "epss_max") {
		t.Fatalf("%s: want exploited 0 and no epss_max without lists", data)
	}
}

func TestAPIStartApp(t *testing.T) {
	r := newRig(t)
	r.containers = []Container{app("a", "sha256:1"), app("b", "sha256:2")}
	r.pass()
	r.scans = nil
	api := newAPI(r)

	if err := api.StartApp("nothing"); !errors.Is(err, ErrNoApp) {
		t.Fatalf("err %v, want ErrNoApp", err)
	}
	if err := api.StartApp("b"); err != nil {
		t.Fatal(err)
	}
	r.waitIdle()
	if len(r.scans) != 1 || r.scans[0] != "sha256:2" {
		t.Fatalf("scans %v", r.scans)
	}
}
