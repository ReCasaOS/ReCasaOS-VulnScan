package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/threat"
	"go.uber.org/zap"
)

const (
	kevURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	// staleAfter: a copy older than this is refreshed at start (a box off or asleep at 05:00).
	staleAfter = 36 * time.Hour
	// listMax caps each download: the real files are a few MB.
	listMax = 20 << 20
)

// NextThreatRun is the next 05:00 on the box's clock: the lists are in place before the 05:30 scan.
func NextThreatRun(now time.Time) time.Time {
	return nextAt(now, 5, 0)
}

// Threat keeps the lists of exploited vulnerabilities fresh: in memory and in Dir.
type Threat struct {
	Dir string
	Get func(ctx context.Context, url string, max int64) ([]byte, error)
	Now func() time.Time
	// MinKEV and MinEPSS refuse a list that came back too small to be the real one.
	MinKEV, MinEPSS int

	mu      sync.RWMutex
	lists   *threat.Lists
	lastErr string
}

// Lists is the copy in use; nil when there is none yet.
func (t *Threat) Lists() *threat.Lists {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.lists
}

func (t *Threat) LastError() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.lastErr
}

// Refresh downloads both lists. Only two valid lists replace the copy in use and the one on
// disk; otherwise the old copy stays and the error is kept for the status.
func (t *Threat) Refresh(ctx context.Context) error {
	l, err := t.download(ctx)
	if err == nil {
		// the scanner creates it too, but not necessarily before the first refresh
		if err = os.MkdirAll(t.Dir, 0o700); err == nil {
			err = threat.Save(t.Dir, l)
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		t.lastErr = err.Error()
		return err
	}
	t.lists, t.lastErr = l, ""

	return nil
}

func (t *Threat) download(ctx context.Context) (*threat.Lists, error) {
	kevBody, err := t.Get(ctx, kevURL, listMax)
	if err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	kev, kevDate, err := threat.ParseKEV(bytes.NewReader(kevBody), t.MinKEV)
	kevBody = nil // not held while EPSS downloads
	if err != nil {
		return nil, err
	}

	epssBody, err := t.Get(ctx, epssURL, listMax)
	if err != nil {
		return nil, fmt.Errorf("epss: %w", err)
	}
	epss, epssDate, err := threat.ParseEPSS(bytes.NewReader(epssBody), t.MinEPSS)
	if err != nil {
		return nil, err
	}

	return &threat.Lists{KEV: kev, EPSS: epss, KEVDate: kevDate, EPSSDate: epssDate}, nil
}

// Run loads the copy on disk, downloads at once when there is none or it is stale, then
// every day at NextThreatRun until ctx ends. Temp files a power cut left in Dir are removed.
// shortcut: a failed download waits for the next 05:00, no retry; add one if boxes stay stale
func (t *Threat) Run(ctx context.Context) {
	// the pattern threat.Save creates its temp files with
	if old, _ := filepath.Glob(filepath.Join(t.Dir, threat.FileName+".tmp*")); len(old) > 0 {
		for _, f := range old {
			_ = os.Remove(f)
		}
	}
	if l, err := threat.Load(t.Dir); err == nil {
		t.mu.Lock()
		t.lists = l
		t.mu.Unlock()
	} else if !errors.Is(err, os.ErrNotExist) {
		logger.Error("the lists of exploited vulnerabilities on disk cannot be read", zap.Error(err))
	}
	if l := t.Lists(); l == nil || t.Now().Sub(l.KEVDate) > staleAfter {
		t.refresh(ctx)
	}
	for {
		now := t.Now()
		timer := time.NewTimer(NextThreatRun(now).Sub(now))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		t.refresh(ctx)
	}
}

// StartThreat runs t in the background when enabled; the channel closes when it has stopped
// (at once when disabled, which downloads nothing).
func StartThreat(ctx context.Context, enabled bool, t *Threat) <-chan struct{} {
	done := make(chan struct{})
	if !enabled {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		t.Run(ctx)
	}()

	return done
}

func (t *Threat) refresh(ctx context.Context) {
	if err := t.Refresh(ctx); err != nil && ctx.Err() == nil {
		logger.Error("the lists of exploited vulnerabilities were not updated", zap.Error(err))
	}
}
