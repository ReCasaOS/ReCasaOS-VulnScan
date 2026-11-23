package service

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/trivy"
)

func init() { logger.LogInitConsoleOnly() }

func someState() State {
	at := time.Date(2026, 11, 23, 5, 30, 0, 0, time.UTC)
	return State{
		Images: map[string]ImageResult{"sha256:aa": {
			ScannedAt: at, DB: at.Add(-time.Hour), OSOnly: true,
			Findings: []trivy.Finding{{ID: "CVE-1", Package: "openssl", Installed: "1", Fixed: "2", Severity: trivy.Critical}},
		}, "sha256:bb": {Skipped: SkippedNoRoom}},
		Told:    map[string][]string{"vaultwarden": {"CVE-1"}},
		LastRun: at, LastError: "the box stayed busy",
	}
}

func TestLoadMissing(t *testing.T) {
	state := Load(filepath.Join(t.TempDir(), "not-there"))
	if state.Images == nil || state.Told == nil || len(state.Images)+len(state.Told) != 0 {
		t.Fatalf("%+v: want two empty maps", state)
	}
}

// A power cut while the file is written leaves this.
func TestLoadTruncated(t *testing.T) {
	dir := t.TempDir()
	for _, content := range []string{`{"Images":{"sha`, ``, `null`, `{"Images":null,"Told":null}`, `[1]`} {
		if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		state := Load(dir)
		if state.Images == nil || state.Told == nil || len(state.Images) != 0 {
			t.Fatalf("%q: %+v, want an empty state", content, state)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "made", "by", "save")
	if err := someState().Save(dir); err != nil {
		t.Fatal(err)
	}
	if got := Load(dir); !reflect.DeepEqual(got, someState()) {
		t.Fatalf("%+v\nwant %+v", got, someState())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("%d files in the state folder, want state.json alone", len(entries))
	}
}

func TestSaveKeepsOldOnFailure(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs a folder the test cannot write to")
	}
	dir := t.TempDir()
	if err := someState().Save(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := (State{}).Save(dir); err == nil {
		t.Fatal("no error from a folder that cannot be written")
	}
	if got := Load(dir); !reflect.DeepEqual(got, someState()) {
		t.Fatalf("the old state is gone: %+v", got)
	}
}
