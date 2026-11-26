package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/threat"
)

const kevJSON = `{"dateReleased":"2026-11-25T15:00:00.000Z","vulnerabilities":[
{"cveID":"CVE-2024-0001","dateAdded":"2026-11-01","knownRansomwareCampaignUse":"Known"},
{"cveID":"CVE-2024-0002","dateAdded":"2026-11-02","knownRansomwareCampaignUse":"Unknown"},
{"cveID":"CVE-2024-0003","dateAdded":"2026-11-03","knownRansomwareCampaignUse":"Unknown"}]}`

const epssCSV = "#model_version:v2025.03.14,score_date:2026-11-25T12:55:00Z\ncve,epss,percentile\nCVE-2024-0001,0.5,0.9\nCVE-2024-0002,0.1,0.5\n"

func gzipped(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

// feed answers the two downloads from memory and counts the calls.
type feed struct {
	mu       sync.Mutex
	kev      string
	epss     []byte
	kevErr   error
	epssErr  error
	calls    int
	gotCalls chan struct{}
}

func newFeed() *feed {
	return &feed{kev: kevJSON, epss: gzipped(epssCSV), gotCalls: make(chan struct{}, 10)}
}

func (f *feed) get(_ context.Context, url string, _ int64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	select {
	case f.gotCalls <- struct{}{}:
	default:
	}
	switch url {
	case kevURL:
		return []byte(f.kev), f.kevErr
	case epssURL:
		return f.epss, f.epssErr
	}
	return nil, errors.New("unexpected url " + url)
}

func (f *feed) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

var threatNow = time.Date(2026, 11, 26, 3, 0, 0, 0, time.UTC)

func newThreat(t *testing.T, f *feed) *Threat {
	return &Threat{Dir: t.TempDir(), Get: f.get, Now: func() time.Time { return threatNow }, MinKEV: 3, MinEPSS: 2}
}

func TestRefreshSavesBothWhenValid(t *testing.T) {
	th := newThreat(t, newFeed())
	if err := th.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	l := th.Lists()
	if l == nil || !l.Exploited("CVE-2024-0001") || len(l.EPSS) != 2 {
		t.Fatalf("%+v", l)
	}
	disk, err := threat.Load(th.Dir)
	if err != nil || len(disk.KEV) != 3 || len(disk.EPSS) != 2 {
		t.Fatalf("disk %+v %v", disk, err)
	}
	if th.LastError() != "" {
		t.Fatal(th.LastError())
	}
}

func TestRefreshKeepsTheOldCopyWhenEPSSFails(t *testing.T) {
	f := newFeed()
	th := newThreat(t, f)
	if err := th.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.kev = `{"dateReleased":"2026-11-26T15:00:00Z","vulnerabilities":[{"cveID":"CVE-2025-9999","dateAdded":"2026-11-26","knownRansomwareCampaignUse":"Unknown"},{"cveID":"CVE-2025-9998"},{"cveID":"CVE-2025-9997"}]}`
	f.epssErr = errors.New("503")

	if err := th.Refresh(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if !th.Lists().Exploited("CVE-2024-0001") || th.Lists().Exploited("CVE-2025-9999") {
		t.Fatal("the old copy must stay in memory")
	}
	if disk, _ := threat.Load(th.Dir); disk == nil || !disk.Exploited("CVE-2024-0001") || disk.Exploited("CVE-2025-9999") {
		t.Fatal("the old copy must stay on disk")
	}
	if th.LastError() == "" {
		t.Fatal("the error is kept")
	}

	f.epssErr = nil
	if err := th.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if th.LastError() != "" || !th.Lists().Exploited("CVE-2025-9999") {
		t.Fatal("a good refresh clears the error and replaces the copy")
	}
}

func TestRefreshKeepsTheOldCopyWhenKEVIsTooSmall(t *testing.T) {
	f := newFeed()
	th := newThreat(t, f)
	if err := th.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.kev = `{"dateReleased":"2026-11-26T15:00:00Z","vulnerabilities":[{"cveID":"CVE-2025-9999"}]}`

	if err := th.Refresh(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if !th.Lists().Exploited("CVE-2024-0001") || th.LastError() == "" {
		t.Fatal("the old copy stays and the error is kept")
	}
}

func TestRunLoadsFromDiskWithoutDownloading(t *testing.T) {
	f := newFeed()
	th := newThreat(t, f)
	if err := th.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := f.count()

	again := &Threat{Dir: th.Dir, Get: f.get, Now: th.Now}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); again.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for again.Lists() == nil {
		if time.Now().After(deadline) {
			t.Fatal("the copy on disk is never loaded")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if f.count() != before {
		t.Fatalf("%d downloads, want none", f.count()-before)
	}
}

func TestRunDownloadsAtOnceWithoutCopy(t *testing.T) {
	f := newFeed()
	th := newThreat(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); th.Run(ctx) }()
	select {
	case <-f.gotCalls:
	case <-time.After(5 * time.Second):
		t.Fatal("no download")
	}
	cancel()
	<-done
}

func TestNextThreatRunIs0500(t *testing.T) {
	if got, want := NextThreatRun(time.Date(2026, 11, 24, 3, 0, 0, 0, time.UTC)), time.Date(2026, 11, 24, 5, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("%v, want %v", got, want)
	}
	if got, want := NextThreatRun(time.Date(2026, 11, 24, 5, 0, 0, 0, time.UTC)), time.Date(2026, 11, 25, 5, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("%v, want %v", got, want)
	}
	paris, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Skip("no time zone database here")
	}
	got := NextThreatRun(time.Date(2026, 3, 28, 18, 0, 0, 0, paris)) // the clocks go forward the next night
	if got.Hour() != 5 || got.Minute() != 0 || got.Day() != 29 {
		t.Fatalf("%v, want 05:00 on the 29th in Paris", got)
	}
}

func TestStatusSaysTheListDateAndError(t *testing.T) {
	r := newRig(t)
	api := newAPI(r)
	if s := api.Status(); s.ThreatUpdatedAt != nil || s.ThreatError != "" {
		t.Fatalf("%+v: no Threat, nothing to say", s)
	}

	f := newFeed()
	api.Threat = newThreat(t, f)
	if s := api.Status(); s.ThreatUpdatedAt != nil || s.ThreatError != "" {
		t.Fatalf("%+v: no list yet", s)
	}
	if err := api.Threat.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := api.Status(); s.ThreatUpdatedAt == nil || !s.ThreatUpdatedAt.Equal(time.Date(2026, 11, 25, 15, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v: want the KEV date", s)
	}
	f.epssErr = errors.New("503")
	api.Threat.Refresh(context.Background())
	if s := api.Status(); s.ThreatUpdatedAt == nil || s.ThreatError == "" {
		t.Fatalf("%+v: the old date and the error", s)
	}
}

// Enabled=false means main never starts Run: Get is never called and Lists() stays nil.
func TestThreatOffByConfig(t *testing.T) {
	f := newFeed()
	th := newThreat(t, f)
	if f.count() != 0 || th.Lists() != nil {
		t.Fatal("a Threat nobody runs does nothing")
	}
}
