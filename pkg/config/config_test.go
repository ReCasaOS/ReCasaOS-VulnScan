package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigDefaultIsOn(t *testing.T) {
	defer func(v ThreatModel) { *ThreatInfo = v }(*ThreatInfo) // the global outlives the test (-count)
	path := filepath.Join(t.TempDir(), "vuln-scan.conf")
	if err := os.WriteFile(path, []byte("[common]\nRuntimePath = /tmp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	InitSetup(path, "")
	if !ThreatInfo.Enabled {
		t.Fatal("a file without [threat] must keep the lists on")
	}

	if err := os.WriteFile(path, []byte("[threat]\nEnabled = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	InitSetup(path, "")
	if ThreatInfo.Enabled {
		t.Fatal("Enabled = false must turn it off")
	}
}
