package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// maxReport bounds what is read of a report: the largest seen on a real box is under 1 MiB.
const maxReport = 64 << 20

// Args is the command line of one scan. The image is read from the Docker daemon alone, the
// scan asks nothing of the network, and only the vulnerability database is ever downloaded
// (never the Java one: 1.5 GB). osOnly leaves the language libraries out, for an image whose
// JAR files Trivy refuses to read without the Java database. Nil for a name Trivy would read
// as an option.
func Args(image, cacheDir string, osOnly bool) []string {
	if image == "" || strings.HasPrefix(image, "-") {
		return nil
	}

	args := []string{
		"image", "--image-src", "docker", "--scanners", "vuln", "--severity", Critical + "," + High, "--ignore-unfixed",
		"--format", "json", "--parallel", "1", "--skip-java-db-update", "--offline-scan", "--disable-telemetry",
		"--skip-version-check", "--timeout", "15m", "--cache-dir", cacheDir,
	}
	if osOnly {
		args = append(args, "--pkg-types", "os")
	}

	return append(args, image)
}

// NeedsJavaDB says that a scan failed because the image holds JAR files and the Java
// database is not there.
func NeedsJavaDB(output []byte) bool {
	return bytes.Contains(output, []byte("Unable to initialize the Java DB"))
}

// Runner runs the scanner.
type Runner struct {
	Bin      string
	CacheDir string
	// TempDir is where Trivy copies the whole image on its first scan.
	TempDir string
	Timeout time.Duration
	// MemoryHigh, when set, runs Trivy in a systemd scope of its own under that cap, out of the
	// service's: a scan of a large image under the service's 512M throttled the API with it until
	// it stopped answering (2026-11-24, 50 minutes, the dashboard lost its Security card).
	MemoryHigh string
}

// scoped is the command line that runs bin in a scope of its own, or bin itself where there
// is no systemd to ask (then the scan shares the service's cap, as before).
func scoped(bin string, args []string, memoryHigh string) (string, []string) {
	if memoryHigh == "" {
		return bin, args
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return bin, args
	}
	run, err := exec.LookPath("systemd-run")
	if err != nil {
		return bin, args
	}
	return run, scopeArgs(bin, args, memoryHigh)
}

// scopeArgs: --scope execs the command in place, so a kill at the deadline still reaches Trivy;
// the nice and idle I/O class of the service are inherited.
func scopeArgs(bin string, args []string, memoryHigh string) []string {
	return append([]string{"--scope", "--quiet", "--collect", "--property=MemoryHigh=" + memoryHigh, "--", bin}, args...)
}

// Scan returns the JSON report of one image. The error of a scan that failed ends with
// Trivy's last words.
func (r Runner) Scan(ctx context.Context, image string, osOnly bool) ([]byte, error) {
	args := Args(image, r.CacheDir, osOnly)
	if args == nil {
		return nil, fmt.Errorf("%q is not an image to scan", image)
	}

	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	name, argv := scoped(r.Bin, args, r.MemoryHigh)
	cmd := exec.CommandContext(ctx, name, argv...)
	cmd.Env = append(os.Environ(), "TMPDIR="+r.TempDir)
	cmd.Stdout = &limited{w: &stdout, left: maxReport}
	cmd.Stderr = &limited{w: &stderr, left: 1 << 20, drop: true}
	cmd.WaitDelay = 5 * time.Second // do not wait for a child that keeps the pipes open

	if err := cmd.Run(); err != nil {
		words := bytes.TrimSpace(stderr.Bytes())
		if i := bytes.LastIndexByte(words, '\n'); i >= 0 {
			words = words[i+1:]
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return nil, fmt.Errorf("trivy: %w: %s", err, words)
	}

	return stdout.Bytes(), nil
}

// DBUpdatedAt is the date of the vulnerability database in the cache, zero when there is none.
func (r Runner) DBUpdatedAt() (time.Time, error) {
	data, err := os.ReadFile(filepath.Join(r.CacheDir, "db", "metadata.json"))
	if errors.Is(err, os.ErrNotExist) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}

	var metadata struct{ UpdatedAt time.Time }
	if err := json.Unmarshal(data, &metadata); err != nil {
		return time.Time{}, err
	}

	return metadata.UpdatedAt, nil
}

// limited fails the write that passes its bound, which stops the command; with drop it
// keeps quiet and throws the rest away instead.
type limited struct {
	w    io.Writer
	left int
	drop bool
}

func (l *limited) Write(p []byte) (int, error) {
	if len(p) > l.left {
		if l.drop {
			return len(p), nil
		}
		return 0, errors.New("output too large")
	}
	l.left -= len(p)

	return l.w.Write(p)
}
