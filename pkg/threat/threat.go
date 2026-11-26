// Package threat reads the CISA list of exploited vulnerabilities (KEV) and
// the EPSS scores, and keeps a reduced copy of both on disk.
package threat

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Lists struct {
	KEV      map[string]KEVEntry // by CVE
	EPSS     map[string]float32  // by CVE, score 0..1
	KEVDate  time.Time           // dateReleased of the catalogue, or download time
	EPSSDate time.Time           // score_date
}

type KEVEntry struct {
	Added      time.Time
	Ransomware bool
}

const fileName = "threat.json.gz"

// maxEPSSBytes caps the decompressed EPSS stream (a variable so a test can lower it).
var maxEPSSBytes int64 = 200 << 20

var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func (l *Lists) Exploited(id string) bool {
	if !cveRe.MatchString(id) {
		return false
	}
	_, ok := l.KEV[id]
	return ok
}

func (l *Lists) Score(id string) (float32, bool) {
	if !cveRe.MatchString(id) {
		return 0, false
	}
	s, ok := l.EPSS[id]
	return s, ok
}

func ParseKEV(r io.Reader, minEntries int) (map[string]KEVEntry, time.Time, error) {
	var doc struct {
		DateReleased    string `json:"dateReleased"`
		Vulnerabilities []struct {
			CVEID      string `json:"cveID"`
			DateAdded  string `json:"dateAdded"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, time.Time{}, fmt.Errorf("kev: %w", err)
	}
	m := make(map[string]KEVEntry, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		if !cveRe.MatchString(v.CVEID) {
			continue
		}
		added, _ := time.Parse("2006-01-02", v.DateAdded) // a bad date stays zero, the CVE still counts
		m[v.CVEID] = KEVEntry{Added: added, Ransomware: v.Ransomware == "Known"}
	}
	if len(m) < minEntries {
		return nil, time.Time{}, fmt.Errorf("kev: %d entries, want at least %d", len(m), minEntries)
	}
	date, err := time.Parse(time.RFC3339, doc.DateReleased)
	if err != nil {
		date = time.Now().UTC()
	}
	return m, date, nil
}

// limitReader fails past n bytes instead of cutting the stream short.
type limitReader struct {
	r io.Reader
	n int64
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.n <= 0 { // at the limit: fine if the stream ends here, an error if more follows
		var b [1]byte
		n, err := l.r.Read(b[:])
		if n > 0 {
			return 0, errors.New("epss: decompressed data over the limit")
		}
		return 0, err
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// ParseEPSS reads a gzip stream: "#model_version:...,score_date:...", "cve,epss,percentile", rows.
func ParseEPSS(r io.Reader, minRows int) (map[string]float32, time.Time, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("epss: %w", err)
	}
	defer zr.Close()
	br := bufio.NewReader(&limitReader{r: zr, n: maxEPSSBytes})

	first, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(first, "#") {
		return nil, time.Time{}, errors.New("epss: missing comment header")
	}
	var date time.Time
	for _, kv := range strings.Split(strings.TrimSpace(first[1:]), ",") {
		if v, ok := strings.CutPrefix(kv, "score_date:"); ok {
			date, err = time.Parse(time.RFC3339, v)
			if err != nil {
				return nil, time.Time{}, fmt.Errorf("epss: score_date: %w", err)
			}
		}
	}
	if date.IsZero() {
		return nil, time.Time{}, errors.New("epss: no score_date in header")
	}

	cr := csv.NewReader(br)
	cr.FieldsPerRecord = -1
	head, err := cr.Read()
	if err != nil || len(head) < 2 || head[0] != "cve" || head[1] != "epss" {
		return nil, time.Time{}, errors.New("epss: missing column header")
	}
	m := make(map[string]float32)
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("epss: %w", err)
		}
		if len(rec) < 2 || !cveRe.MatchString(rec[0]) {
			continue
		}
		s, err := strconv.ParseFloat(rec[1], 32)
		if err != nil || !(s >= 0 && s <= 1) { // also refuses NaN and Inf, which JSON cannot hold
			continue
		}
		m[rec[0]] = float32(s)
	}
	if len(m) < minRows {
		return nil, time.Time{}, fmt.Errorf("epss: %d rows, want at least %d", len(m), minRows)
	}
	return m, date, nil
}

// Save writes dir/threat.json.gz through a temporary file in the same dir.
func Save(dir string, l *Lists) error {
	tmp, err := os.CreateTemp(dir, fileName+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	zw := gzip.NewWriter(tmp)
	err = json.NewEncoder(zw).Encode(l)
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if serr := tmp.Sync(); err == nil {
		err = serr
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, fileName))
}

// Load returns an error wrapping os.ErrNotExist when nothing was saved.
func Load(dir string) (*Lists, error) {
	f, err := os.Open(filepath.Join(dir, fileName))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var l Lists
	if err := json.NewDecoder(zr).Decode(&l); err != nil {
		return nil, err
	}
	return &l, nil
}

// Fetch gets url with at most one redirect, to the same host, and a body of at most max bytes.
func Fetch(ctx context.Context, c *http.Client, url string, max int64) ([]byte, error) {
	if c == nil {
		c = http.DefaultClient
	}
	cc := *c
	cc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 1 {
			return errors.New("fetch: more than one redirect")
		}
		if req.URL.Host != via[0].URL.Host || req.URL.Scheme != via[0].URL.Scheme {
			return fmt.Errorf("fetch: redirect to another origin (%s://%s)", req.URL.Scheme, req.URL.Host)
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ReCasaOS-VulnScan")
	resp, err := cc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("fetch: body over %d bytes", max)
	}
	return b, nil
}
