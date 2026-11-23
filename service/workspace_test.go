package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

type rootDir struct {
	dir   string
	err   error
	asked int
}

func (r *rootDir) Containers(context.Context) ([]Container, error) { return nil, nil }
func (r *rootDir) RootDir(context.Context) (string, error) {
	r.asked++
	return r.dir, r.err
}

func TestWorkspaceNamedInTheConfiguration(t *testing.T) {
	docker := &rootDir{dir: "/var/lib/docker"}
	w := &Workspace{Fixed: "/mnt/big/scan", Docker: docker}

	if dir, err := w.Dir(context.Background()); err != nil || dir != "/mnt/big/scan" || docker.asked != 0 {
		t.Fatalf("%q, err %v, docker asked %d times", dir, err, docker.asked)
	}
}

// Beside Docker's data, where the room is: never on the root filesystem by default.
func TestWorkspaceBesideDockersData(t *testing.T) {
	docker := &rootDir{dir: "/DATA/docker/"}
	w := &Workspace{Docker: docker}

	want := filepath.Join(filepath.FromSlash("/DATA"), "casaos-vuln-scan")
	for range 2 {
		if dir, err := w.Dir(context.Background()); err != nil || dir != want {
			t.Fatalf("%q, err %v; want %q", dir, err, want)
		}
	}
	if docker.asked != 1 {
		t.Fatalf("docker asked %d times, want once", docker.asked)
	}
	if tmp, _ := w.Tmp(context.Background()); tmp != filepath.Join(want, "tmp") {
		t.Fatalf("tmp %q", tmp)
	}
}

// Docker that does not answer yet is no reason to work somewhere else: there is no folder
// until it does.
func TestWorkspaceWaitsForDocker(t *testing.T) {
	docker := &rootDir{err: errors.New("Cannot connect to the Docker daemon")}
	w := &Workspace{Docker: docker}

	if dir, err := w.Dir(context.Background()); err == nil || dir != "" {
		t.Fatalf("%q, err %v; want no folder", dir, err)
	}
	if _, err := w.Tmp(context.Background()); err == nil {
		t.Fatal("a temporary folder although Docker does not answer")
	}
	if at, err := (LazyTrivy{Work: w}).DBUpdatedAt(); err != nil || !at.IsZero() {
		t.Fatalf("database date %v, err %v; want none", at, err)
	}

	docker.dir, docker.err = "/var/lib/docker", nil
	if dir, err := w.Dir(context.Background()); err != nil || dir != filepath.Join(filepath.FromSlash("/var/lib"), "casaos-vuln-scan") {
		t.Fatalf("%q, err %v", dir, err)
	}
}
