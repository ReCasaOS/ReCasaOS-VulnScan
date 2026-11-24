package service

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/trivy"
)

// Workspace is the folder the scans work in: Trivy's cache (its database is 1.7 GB) and the
// temporary copy of the image being scanned. It is the folder the configuration names, or
// one beside Docker's data, where the room is. While Docker does not say where its data is
// there is no workspace: the scans wait, they never fall back on the root filesystem.
type Workspace struct {
	// Fixed is the folder the configuration names; empty to put it beside Docker's data.
	Fixed  string
	Docker Docker

	mu  sync.Mutex
	dir string
}

func (w *Workspace) Dir(ctx context.Context) (string, error) {
	if w.Fixed != "" {
		return w.Fixed, nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dir == "" {
		root, err := w.Docker.RootDir(ctx)
		if err != nil {
			return "", err
		}
		w.dir = filepath.Join(filepath.Dir(filepath.Clean(root)), "casaos-vuln-scan")
	}

	return w.dir, nil
}

// known is the workspace when it has been found, without asking Docker.
func (w *Workspace) known() string {
	if w.Fixed != "" {
		return w.Fixed
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.dir
}

// Tmp is where Trivy copies an image.
func (w *Workspace) Tmp(ctx context.Context) (string, error) {
	dir, err := w.Dir(ctx)
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, "tmp"), nil
}

// LazyTrivy is the scanner the archive ships, working in a Workspace that may not be known
// yet when the service starts.
type LazyTrivy struct {
	Bin     string
	Timeout time.Duration
	Work    *Workspace
	// MemoryHigh is the cap of a scan, in a scope of its own (trivy.Runner)
	MemoryHigh string
}

func (l LazyTrivy) Scan(ctx context.Context, image string, osOnly bool) ([]byte, error) {
	dir, err := l.Work.Dir(ctx)
	if err != nil {
		return nil, err
	}
	cache, tmp := filepath.Join(dir, "cache"), filepath.Join(dir, "tmp")
	for _, d := range []string{cache, tmp} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}

	return trivy.Runner{Bin: l.Bin, CacheDir: cache, TempDir: tmp, Timeout: l.Timeout, MemoryHigh: l.MemoryHigh}.Scan(ctx, image, osOnly)
}

// DBUpdatedAt is the date of the vulnerability database; zero while there is none, or no
// workspace yet.
func (l LazyTrivy) DBUpdatedAt() (time.Time, error) {
	dir := l.Work.known()
	if dir == "" {
		return time.Time{}, nil
	}

	return trivy.Runner{CacheDir: filepath.Join(dir, "cache")}.DBUpdatedAt()
}
