package service

import (
	"context"
	"maps"
	"strings"
	"sync"
	"time"
)

// followRetry is the wait before the stream of events is asked again, and before a change
// found while a pass runs is looked at again. A var, so tests can shorten it.
var followRetry = 10 * time.Second

// Follow scans when the images the apps run are no longer those of the last pass: an app
// was installed, updated or removed, and its results must not wait for the night. created
// tells each container made until its stream is lost (DockerSocket.Created); it is asked
// again then, and what changed meanwhile is looked for. Follow returns when ctx ends.
func (s *Scanner) Follow(ctx context.Context, created func(ctx context.Context, on func()) error) {
	wake := make(chan struct{}, 1)
	poke := func() {
		select {
		case wake <- struct{}{}:
		default: // a look is owed already: it will see this change too
		}
	}

	var stream sync.WaitGroup
	defer stream.Wait()
	stream.Add(1)
	go func() {
		defer stream.Done()
		for {
			poke() // the stream was lost for a while, or never asked: look once
			_ = created(ctx, poke)
			select {
			case <-ctx.Done():
				return
			case <-time.After(followRetry):
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
		}
		if !s.appsChanged(ctx) {
			continue
		}
		// the pass waits by itself for the update that made the containers to be over
		if s.Pass(ctx) == ErrRunning {
			// the pass that runs may have listed the containers before this change
			select {
			case <-ctx.Done():
				return
			case <-time.After(followRetry):
				poke()
			}
		}
	}
}

// appsChanged says whether the apps run other images than at the last pass. Containers
// made by hand do not count: a job that makes one every minute must not scan every minute,
// and the night scans them.
func (s *Scanner) appsChanged(ctx context.Context) bool {
	listed, err := s.Docker.Containers(ctx)
	if err != nil {
		return false // Docker does not answer: the stream is lost too, and looks again
	}
	_, inventory := s.Snapshot()

	return !maps.Equal(appImages(GroupImages(listed)), appImages(inventory))
}

// appImages is the apps of each image an app uses.
func appImages(images []Image) map[string]string {
	apps := map[string]string{}
	for _, image := range images {
		if len(image.Apps) > 0 {
			apps[image.ID] = strings.Join(image.Apps, "\n")
		}
	}

	return apps
}
