package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Container is one container of the box, running or not, and the image it was made from.
type Container struct {
	Name    string
	ImageID string
	// Project is the compose project, which is the app; empty for a container made by hand.
	Project string
	// ImageSize is 0 when the image is gone.
	ImageSize int64
}

// Image is one image to scan, and who uses it.
type Image struct {
	ID   string
	Size int64
	// Apps are the compose projects with a container of this image.
	Apps []string
	// Loose are the containers of this image that belong to no compose project.
	Loose []string
}

// GroupImages gives one entry per image, sorted by id, with its apps and loose containers
// sorted and named once.
func GroupImages(containers []Container) []Image {
	byID := map[string]*Image{}
	for _, c := range containers {
		image := byID[c.ImageID]
		if image == nil {
			image = &Image{ID: c.ImageID, Size: c.ImageSize}
			byID[c.ImageID] = image
		}
		if c.Project != "" {
			image.Apps = append(image.Apps, c.Project)
		} else {
			image.Loose = append(image.Loose, c.Name)
		}
	}

	images := make([]Image, 0, len(byID))
	for _, image := range byID {
		slices.Sort(image.Apps)
		slices.Sort(image.Loose)
		image.Apps, image.Loose = slices.Compact(image.Apps), slices.Compact(image.Loose)
		images = append(images, *image)
	}
	slices.SortFunc(images, func(a, b Image) int { return strings.Compare(a.ID, b.ID) })

	return images
}

// Docker is what the scanner asks of the Docker daemon.
type Docker interface {
	Containers(ctx context.Context) ([]Container, error)
	RootDir(ctx context.Context) (string, error)
}

// DockerSocket asks the daemon on its unix socket. Three reads need no client library.
type DockerSocket struct {
	client *http.Client
	base   string
}

func NewDockerSocket(path string) *DockerSocket {
	return &DockerSocket{
		base: "http://docker",
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			}},
		},
	}
}

func (d *DockerSocket) get(ctx context.Context, path string, into interface{}) (status int, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+path, nil)
	if err != nil {
		return 0, err
	}
	response, err := d.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return response.StatusCode, fmt.Errorf("docker answered %s to %s", response.Status, path)
	}

	return response.StatusCode, json.NewDecoder(io.LimitReader(response.Body, 64<<20)).Decode(into)
}

// Containers lists every container, stopped ones too: a stopped app is still installed.
func (d *DockerSocket) Containers(ctx context.Context) ([]Container, error) {
	var listed []struct {
		Names   []string
		ImageID string
		Labels  map[string]string
	}
	if _, err := d.get(ctx, "/containers/json?all=1", &listed); err != nil {
		return nil, err
	}

	sizes := map[string]int64{}
	containers := make([]Container, 0, len(listed))
	for _, l := range listed {
		if _, asked := sizes[l.ImageID]; !asked {
			var image struct{ Size int64 }
			// an image removed since its container was made answers 404: no size, and the scan says why
			if status, err := d.get(ctx, "/images/"+url.PathEscape(l.ImageID)+"/json", &image); err != nil && status != http.StatusNotFound {
				return nil, err
			}
			sizes[l.ImageID] = image.Size
		}

		name := ""
		if len(l.Names) > 0 {
			name = strings.TrimPrefix(l.Names[0], "/")
		}
		containers = append(containers, Container{Name: name, ImageID: l.ImageID, Project: l.Labels["com.docker.compose.project"], ImageSize: sizes[l.ImageID]})
	}

	return containers, nil
}

// RootDir is where Docker keeps its data.
func (d *DockerSocket) RootDir(ctx context.Context) (string, error) {
	var info struct{ DockerRootDir string }
	if _, err := d.get(ctx, "/info", &info); err != nil {
		return "", err
	}
	if info.DockerRootDir == "" {
		return "", fmt.Errorf("docker does not say where its data is")
	}

	return info.DockerRootDir, nil
}
