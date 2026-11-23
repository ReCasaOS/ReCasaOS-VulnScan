package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestGroupImagesSharedImage(t *testing.T) {
	images := GroupImages([]Container{
		{Name: "b-1", ImageID: "sha256:1", Project: "b", ImageSize: 10},
		{Name: "a-1", ImageID: "sha256:1", Project: "a", ImageSize: 10},
		{Name: "a-2", ImageID: "sha256:1", Project: "a", ImageSize: 10},
	})
	want := []Image{{ID: "sha256:1", Size: 10, Apps: []string{"a", "b"}}}
	if !reflect.DeepEqual(images, want) {
		t.Fatalf("%+v, want %+v", images, want)
	}
}

func TestGroupImagesLoose(t *testing.T) {
	images := GroupImages([]Container{{Name: "byhand", ImageID: "sha256:1", ImageSize: 10}})
	want := []Image{{ID: "sha256:1", Size: 10, Loose: []string{"byhand"}}}
	if !reflect.DeepEqual(images, want) {
		t.Fatalf("%+v, want %+v", images, want)
	}
}

func TestGroupImagesTwoServices(t *testing.T) {
	images := GroupImages([]Container{
		{Name: "app-web", ImageID: "sha256:2", Project: "app", ImageSize: 20},
		{Name: "app-db", ImageID: "sha256:1", Project: "app", ImageSize: 10},
	})
	want := []Image{{ID: "sha256:1", Size: 10, Apps: []string{"app"}}, {ID: "sha256:2", Size: 20, Apps: []string{"app"}}}
	if !reflect.DeepEqual(images, want) {
		t.Fatalf("%+v, want %+v", images, want)
	}
}

// What Docker 27 answers, cut to the fields that are read.
func dockerStub(t *testing.T) *DockerSocket {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("all") != "1" {
			t.Errorf("stopped containers are not asked for: %s", r.URL)
		}
		_, _ = w.Write([]byte(`[
		 {"Names":["/vaultwarden"],"ImageID":"sha256:aa","Labels":{"com.docker.compose.project":"vaultwarden"}},
		 {"Names":["/byhand"],"ImageID":"sha256:bb","Labels":{}},
		 {"Names":["/gone"],"ImageID":"sha256:cc","Labels":{"com.docker.compose.project":"gone"}}]`))
	})
	mux.HandleFunc("/images/sha256:aa/json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"Size":310969164}`)) })
	mux.HandleFunc("/images/sha256:bb/json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"Size":5}`)) })
	mux.HandleFunc("/info", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"DockerRootDir":"/var/lib/docker"}`))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &DockerSocket{client: server.Client(), base: server.URL}
}

func TestDockerContainers(t *testing.T) {
	containers, err := dockerStub(t).Containers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// the image of "gone" was removed since: its container is listed with no size
	want := []Container{
		{Name: "vaultwarden", ImageID: "sha256:aa", Project: "vaultwarden", ImageSize: 310969164},
		{Name: "byhand", ImageID: "sha256:bb", ImageSize: 5},
		{Name: "gone", ImageID: "sha256:cc", Project: "gone"},
	}
	if !reflect.DeepEqual(containers, want) {
		t.Fatalf("%+v\nwant %+v", containers, want)
	}
}

func TestDockerRootDir(t *testing.T) {
	if dir, err := dockerStub(t).RootDir(context.Background()); err != nil || dir != "/var/lib/docker" {
		t.Fatalf("%q, err %v", dir, err)
	}
}

func TestDockerDown(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	docker := &DockerSocket{client: server.Client(), base: server.URL}
	server.Close()
	if _, err := docker.Containers(context.Background()); err == nil {
		t.Fatal("no error from a daemon that does not answer")
	}
}
