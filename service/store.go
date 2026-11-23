package service

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/trivy"
	"go.uber.org/zap"
)

// Why an image has no findings to show. They are shown to the administrator as they are.
const (
	SkippedNoRoom = "not enough room"
	SkippedFailed = "scan failed"
)

// ImageResult is what the last scan of one image found.
type ImageResult struct {
	ScannedAt time.Time
	// DB is the date of the vulnerability database the image was scanned with.
	DB       time.Time
	Findings []trivy.Finding
	// Skipped is empty for an image that was scanned.
	Skipped string
	// OSOnly: the image holds Java libraries, which were not checked.
	OSOnly bool
}

// State is everything the service keeps between two starts.
type State struct {
	// Inventory is the images the last pass found on the box, and who uses each.
	Inventory []Image
	// Images are the results, by image id.
	Images map[string]ImageResult
	// Told are the ids of the critical vulnerabilities already announced, by app.
	Told      map[string][]string
	LastRun   time.Time
	LastError string
}

const stateFile = "state.json"

// Load reads the state kept in dir. A file that is not there or cannot be read is an empty
// state: the next scan rebuilds it, and at worst a vulnerability is announced twice.
func Load(dir string) State {
	var state State

	data, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err == nil {
		err = json.Unmarshal(data, &state)
	}
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logger.Error("the kept scan results cannot be read, starting without them", zap.String("dir", dir), zap.Error(err))
		}
		state = State{}
	}
	if state.Images == nil {
		state.Images = map[string]ImageResult{}
	}
	if state.Told == nil {
		state.Told = map[string][]string{}
	}

	return state
}

// Save writes the state beside its file and renames it over, so that a cut leaves the old
// state or the new one.
func (s State) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, stateFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // nothing to remove once renamed

	if _, err := tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}

	return os.Rename(tmp.Name(), filepath.Join(dir, stateFile))
}
