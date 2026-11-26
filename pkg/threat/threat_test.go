package threat

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func open(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func TestParseKEVReadsTheCatalogue(t *testing.T) {
	m, date, err := ParseKEV(open(t, "kev.json"), 3)
	if err != nil {
		t.Fatal(err)
	}
	l := &Lists{KEV: m}
	if !l.Exploited("CVE-2024-10441") {
		t.Fatal("CVE-2024-10441 should be exploited")
	}
	e := m["CVE-2024-10441"]
	if e.Added.Format("2006-01-02") != "2026-11-18" || !e.Ransomware {
		t.Fatalf("bad entry %+v", e)
	}
	if m["CVE-2026-103406"].Ransomware {
		t.Fatal("Unknown must not be ransomware")
	}
	if date.Format("2006-01-02") != "2026-11-25" {
		t.Fatalf("bad date %v", date)
	}
}

func TestParseKEVRefusesTooFew(t *testing.T) {
	if _, _, err := ParseKEV(open(t, "kev.json"), 5); err == nil {
		t.Fatal("want error")
	}
}

func TestParseKEVRefusesGarbage(t *testing.T) {
	if _, _, err := ParseKEV(strings.NewReader("<html>nope</html>"), 0); err == nil {
		t.Fatal("want error")
	}
}

func TestParseEPSSReadsScores(t *testing.T) {
	m, date, err := ParseEPSS(open(t, "epss.csv.gz"), 10)
	if err != nil {
		t.Fatal(err)
	}
	l := &Lists{EPSS: m}
	s, ok := l.Score("CVE-1999-0001")
	if !ok || s < 0.0475 || s > 0.0476 {
		t.Fatalf("score %v %v", s, ok)
	}
	if date.Format(time.RFC3339) != "2026-11-25T12:00:23Z" {
		t.Fatalf("date %v", date)
	}
	if _, ok := l.Score("CVE-2000-9999"); ok {
		t.Fatal("unknown CVE must have no score")
	}
}

func TestParseEPSSRefusesMissingHeader(t *testing.T) {
	_, _, err := ParseEPSS(bytes.NewReader(gz(t, "cve,epss,percentile\nCVE-1999-0001,0.1,0.2\n")), 1)
	if err == nil {
		t.Fatal("want error")
	}
}

func TestParseEPSSRefusesTruncated(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("#model_version:v1,score_date:2026-11-25T12:00:23Z\ncve,epss,percentile\n")
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&sb, "CVE-2020-%04d,0.%05d,0.5\n", i+1000, i)
	}
	full := gz(t, sb.String())
	if _, _, err := ParseEPSS(bytes.NewReader(full[:len(full)/2]), 1); err == nil {
		t.Fatal("want error on cut gzip")
	}
	if _, _, err := ParseEPSS(bytes.NewReader(full), 1); err != nil {
		t.Fatal(err)
	}
}

func TestParseEPSSRefusesTooFewRows(t *testing.T) {
	if _, _, err := ParseEPSS(open(t, "epss.csv.gz"), 1000); err == nil {
		t.Fatal("want error")
	}
}

func TestOnlyCVEIDs(t *testing.T) {
	l := &Lists{
		KEV:  map[string]KEVEntry{"GHSA-xxxx-yyyy-zzzz": {}, "CVE-2024-1": {}, "CVE-2024-0001": {}},
		EPSS: map[string]float32{"GHSA-xxxx-yyyy-zzzz": 1},
	}
	if l.Exploited("GHSA-xxxx-yyyy-zzzz") || l.Exploited("CVE-2024-1") {
		t.Fatal("non CVE ids must be false")
	}
	if _, ok := l.Score("GHSA-xxxx-yyyy-zzzz"); ok {
		t.Fatal("non CVE ids must have no score")
	}
	if !l.Exploited("CVE-2024-0001") {
		t.Fatal("valid id should answer")
	}
	// parsing drops them too
	body := `{"dateReleased":"2026-11-25T19:48:12Z","vulnerabilities":[{"cveID":"GHSA-x","dateAdded":"2026-01-01"},{"cveID":"CVE-2024-0001","dateAdded":"2026-01-01"}]}`
	m, _, err := ParseKEV(strings.NewReader(body), 1)
	if err != nil || len(m) != 1 {
		t.Fatalf("%v %v", m, err)
	}
}

func sample() *Lists {
	return &Lists{
		KEV:      map[string]KEVEntry{"CVE-2024-0001": {Added: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), Ransomware: true}},
		EPSS:     map[string]float32{"CVE-2024-0001": 0.5, "CVE-2024-0002": 0.25},
		KEVDate:  time.Date(2026, 11, 25, 19, 0, 0, 0, time.UTC),
		EPSSDate: time.Date(2026, 11, 25, 12, 0, 23, 0, time.UTC),
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := sample()
	if err := Save(dir, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !out.KEVDate.Equal(in.KEVDate) || !out.EPSSDate.Equal(in.EPSSDate) {
		t.Fatalf("dates %v %v", out.KEVDate, out.EPSSDate)
	}
	e := out.KEV["CVE-2024-0001"]
	if !e.Added.Equal(in.KEV["CVE-2024-0001"].Added) || !e.Ransomware {
		t.Fatalf("kev %+v", e)
	}
	if s, ok := out.Score("CVE-2024-0002"); !ok || s != 0.25 {
		t.Fatalf("score %v %v", s, ok)
	}
	if _, err := Load(t.TempDir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want ErrNotExist, got %v", err)
	}
}

func TestSaveLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, sample()); err != nil {
		t.Fatal(err)
	}
	if err := Save(dir, sample()); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != "threat.json.gz" {
		t.Fatalf("dir holds %v", ents)
	}
}

func TestFetchRefusesOtherHostRedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) }))
	defer other.Close()
	// 127.0.0.1 and localhost are different hosts for the redirect check
	target := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL, 100); err == nil {
		t.Fatal("want error")
	}
}

func TestFetchFollowsOneSameHostRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/current", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "real.gz") // relative, as EPSS does
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/real.gz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hello")) })
	mux.HandleFunc("/loop1", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop2", http.StatusFound) })
	mux.HandleFunc("/loop2", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/real.gz", http.StatusFound) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	b, err := Fetch(context.Background(), srv.Client(), srv.URL+"/current", 100)
	if err != nil || string(b) != "hello" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL+"/loop1", 100); err == nil {
		t.Fatal("two redirects must fail")
	}
}

func TestFetchRefusesTooBig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(make([]byte, 11)) }))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL, 10); err == nil {
		t.Fatal("want error")
	}
	if b, err := Fetch(context.Background(), srv.Client(), srv.URL, 11); err != nil || len(b) != 11 {
		t.Fatalf("exactly max must pass: %v", err)
	}
}

func TestFetchRefusesNon200(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL, 100); err == nil {
		t.Fatal("want error")
	}
}

func TestParseEPSSLimitsDecompression(t *testing.T) {
	old := maxEPSSBytes
	maxEPSSBytes = 1000
	defer func() { maxEPSSBytes = old }()
	body := "#model_version:v1,score_date:2026-11-25T12:00:23Z\ncve,epss,percentile\n" + strings.Repeat("CVE-2020-0001,0.1,0.2\n", 200)
	if _, _, err := ParseEPSS(bytes.NewReader(gz(t, body)), 1); err == nil {
		t.Fatal("want error past the limit")
	}
}

// 300 000 synthetic scores must stay under 40 MB.
func TestEPSSTableMemory(t *testing.T) {
	const n = 300000
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	m := make(map[string]float32)
	for i := 0; i < n; i++ {
		m[fmt.Sprintf("CVE-%04d-%05d", 2000+i/10000, i%10000)] = float32(i%1000) / 1000
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	used := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("%d scores: %.1f MB", len(m), float64(used)/1e6)
	if len(m) != n || used > 40<<20 {
		t.Fatalf("len %d, %d bytes", len(m), used)
	}
	runtime.KeepAlive(m)
}

func TestFetchSendsOurUserAgentOnEveryHop(t *testing.T) {
	var agents []string
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		agents = append(agents, r.UserAgent())
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		agents = append(agents, r.UserAgent())
		w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL+"/a", 10); err != nil {
		t.Fatal(err)
	}
	if len(agents) != 2 || agents[0] != "ReCasaOS-VulnScan" || agents[1] != "ReCasaOS-VulnScan" {
		t.Fatalf("agents %v", agents)
	}
}

func TestFetchRefusesSchemeDowngrade(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+r.Host+"/x", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL, 10); err == nil || !strings.Contains(err.Error(), "another origin") {
		t.Fatalf("want origin error, got %v", err)
	}
}

func TestParseEPSSSkipsNaNAndSaveWorks(t *testing.T) {
	body := "#model_version:v1,score_date:2026-11-25T12:00:23Z\ncve,epss,percentile\nCVE-2024-0001,NaN,0.1\nCVE-2024-0002,+Inf,0.1\nCVE-2024-0003,0.5,0.1\n"
	m, date, err := ParseEPSS(bytes.NewReader(gz(t, body)), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 {
		t.Fatalf("NaN and Inf rows must be skipped: %v", m)
	}
	if err := Save(t.TempDir(), &Lists{EPSS: m, EPSSDate: date}); err != nil {
		t.Fatal(err)
	}
}

func TestParseEPSSStreamExactlyAtLimitPasses(t *testing.T) {
	body := "#model_version:v1,score_date:2026-11-25T12:00:23Z\ncve,epss,percentile\nCVE-2020-0001,0.1,0.2\n"
	old := maxEPSSBytes
	defer func() { maxEPSSBytes = old }()
	maxEPSSBytes = int64(len(body))
	if _, _, err := ParseEPSS(bytes.NewReader(gz(t, body)), 1); err != nil {
		t.Fatalf("exact limit must pass: %v", err)
	}
	maxEPSSBytes--
	if _, _, err := ParseEPSS(bytes.NewReader(gz(t, body)), 1); err == nil {
		t.Fatal("one byte over must fail")
	}
}
