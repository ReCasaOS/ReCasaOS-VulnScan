package trivy

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestArgs(t *testing.T) {
	args := Args("sha256:abc", "/work/cache", false)
	for _, pair := range [][2]string{
		{"--severity", "CRITICAL,HIGH"}, {"--parallel", "1"}, {"--image-src", "docker"}, {"--scanners", "vuln"},
		{"--format", "json"}, {"--cache-dir", "/work/cache"}, {"--timeout", "15m"},
	} {
		if i := slices.Index(args, pair[0]); i < 0 || args[i+1] != pair[1] {
			t.Errorf("%s %s is not in %v", pair[0], pair[1], args)
		}
	}
	for _, flag := range []string{"image", "--ignore-unfixed", "--skip-java-db-update", "--offline-scan", "--disable-telemetry", "--skip-version-check"} {
		if !slices.Contains(args, flag) {
			t.Errorf("%s is not in %v", flag, args)
		}
	}
	if args[len(args)-1] != "sha256:abc" || args[0] != "image" {
		t.Errorf("%v: want `image` first and the image last", args)
	}
	if slices.Contains(args, "--pkg-types") {
		t.Errorf("%v: --pkg-types without osOnly", args)
	}
}

func TestArgsOSOnly(t *testing.T) {
	args := Args("sha256:abc", "/work/cache", true)
	if i := slices.Index(args, "--pkg-types"); i < 0 || args[i+1] != "os" {
		t.Errorf("%v: want --pkg-types os", args)
	}
}

// An image whose name starts with a dash would be read by Trivy as an option.
func TestArgsRefusesAnOption(t *testing.T) {
	for _, image := range []string{"-o/etc/passwd", "--config=x", ""} {
		if args := Args(image, "/work/cache", false); args != nil {
			t.Errorf("%q: %v, want nil", image, args)
		}
	}
}

// The line Trivy 0.76.2 ended with on an image that holds JAR files (2026-11-23).
const javaFatal = `2026-11-23T22:02:30Z	FATAL	Fatal error	run error: image scan error: scan error: scan failed: failed analysis: analyze error: pipeline error: failed to analyze layer (sha256:614e): post analysis error: post analysis error: Unable to initialize the Java DB: Java DB update failed: '--skip-java-db-update' cannot be specified on the first run`

func TestNeedsJavaDB(t *testing.T) {
	if !NeedsJavaDB([]byte(javaFatal)) {
		t.Error("the Java DB line is not recognised")
	}
	if NeedsJavaDB([]byte("FATAL	Fatal error	run error: unable to find the specified image")) {
		t.Error("another error is taken for the Java DB one")
	}
}

func script(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a shell script as the scanner")
	}
	path := filepath.Join(t.TempDir(), "trivy")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestScanReturnsTheReport(t *testing.T) {
	work := t.TempDir()
	// the report goes to stdout; TMPDIR is the runner's
	bin := script(t, `for a; do last=$a; done; echo "{\"tmp\":\"$TMPDIR\",\"last\":\"$last\"}"`)
	out, err := Runner{Bin: bin, CacheDir: work, TempDir: work, Timeout: time.Minute}.Scan(context.Background(), "sha256:abc", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"tmp":"` + work + `","last":"sha256:abc"}`; strings.TrimSpace(string(out)) != want {
		t.Fatalf("%s, want %s", out, want)
	}
}

func TestScanFailureCarriesTrivysWords(t *testing.T) {
	bin := script(t, `echo "FATAL the reason" >&2; exit 1`)
	_, err := Runner{Bin: bin, CacheDir: t.TempDir(), TempDir: t.TempDir(), Timeout: time.Minute}.Scan(context.Background(), "sha256:abc", false)
	if err == nil || !strings.Contains(err.Error(), "FATAL the reason") {
		t.Fatalf("err %v; want Trivy's last words in it", err)
	}
}

func TestScanTimeout(t *testing.T) {
	bin := script(t, `sleep 30`)
	start := time.Now()
	_, err := Runner{Bin: bin, CacheDir: t.TempDir(), TempDir: t.TempDir(), Timeout: 50 * time.Millisecond}.Scan(context.Background(), "sha256:abc", false)
	if err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("err %v after %s; want an error at once", err, time.Since(start))
	}
}

func TestDBUpdatedAt(t *testing.T) {
	cache := t.TempDir()
	if at, err := (Runner{CacheDir: cache}).DBUpdatedAt(); err != nil || !at.IsZero() {
		t.Fatalf("no database: %v, err %v; want zero and no error", at, err)
	}
	if err := os.MkdirAll(filepath.Join(cache, "db"), 0o755); err != nil {
		t.Fatal(err)
	}
	// the file Trivy 0.76.2 wrote on 2026-11-23
	metadata := `{"Version":2,"NextUpdate":"2026-11-24T19:02:50.412494606Z","UpdatedAt":"2026-11-23T19:02:50.412495Z","DownloadedAt":"2026-11-23T21:56:20.929430392Z"}`
	if err := os.WriteFile(filepath.Join(cache, "db", "metadata.json"), []byte(metadata), 0o644); err != nil {
		t.Fatal(err)
	}
	at, err := Runner{CacheDir: cache}.DBUpdatedAt()
	if err != nil || !at.Equal(time.Date(2026, 11, 23, 19, 2, 50, 412495000, time.UTC)) {
		t.Fatalf("%v, err %v", at, err)
	}
}

func TestAScanRunsInAScopeOfItsOwn(t *testing.T) {
	args := scopeArgs("/usr/bin/casaos-trivy", []string{"image", "sha256:abc"}, "1536M")
	want := []string{"--scope", "--quiet", "--collect", "--property=MemoryHigh=1536M", "--", "/usr/bin/casaos-trivy", "image", "sha256:abc"}
	if !slices.Equal(args, want) {
		t.Fatalf("%v, want %v", args, want)
	}
	// no cap asked: Trivy itself
	if bin, args := scoped("/usr/bin/casaos-trivy", []string{"image"}, ""); bin != "/usr/bin/casaos-trivy" || !slices.Equal(args, []string{"image"}) {
		t.Fatalf("%s %v", bin, args)
	}
}
