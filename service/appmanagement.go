package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/external"
)

// AppManagement reads two things of the app-management service, as one of the box's own
// services: what runs on the apps, and which apps an update is offered for.
type AppManagement struct {
	RuntimePath string
}

var appManagementClient = &http.Client{Timeout: 10 * time.Second}

func (a AppManagement) get(ctx context.Context, path string, into interface{}) error {
	address, err := os.ReadFile(filepath.Join(a.RuntimePath, external.AppManageURLFilename))
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSpace(string(address))+path, nil)
	if err != nil {
		return err
	}
	// the address is one the service wrote for the box's services: a loopback one
	request.Header.Set("Authorization", external.InternalAuthorization(a.RuntimePath))

	response, err := appManagementClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("app-management answered %s to %s", response.Status, path)
	}

	return json.NewDecoder(io.LimitReader(response.Body, 64<<20)).Decode(into)
}

// Busy says whether an operation runs on an app (an update, a backup, a restore) or an
// upgrade of the operating system is open.
func (a AppManagement) Busy(ctx context.Context) (bool, error) {
	var answer struct {
		Operations    []json.RawMessage `json:"operations"`
		OSUpgradeOpen bool              `json:"os_upgrade_open"`
	}
	if err := a.get(ctx, "/v2/app_management/operations", &answer); err != nil {
		return false, err
	}

	return len(answer.Operations) > 0 || answer.OSUpgradeOpen, nil
}

// Updates says, for every app of the grid, whether an update is offered: what the Update
// button of the dashboard would apply. A newer version of a tag an app is pinned to is not
// one: app-management only says it, and nothing applies it.
func (a AppManagement) Updates(ctx context.Context) (map[string]bool, error) {
	var answer struct {
		Data []struct {
			Name            string `json:"name"`
			UpdateAvailable bool   `json:"update_available"`
		} `json:"data"`
	}
	if err := a.get(ctx, "/v2/app_management/web/appgrid", &answer); err != nil {
		return nil, err
	}

	updates := make(map[string]bool, len(answer.Data))
	for _, item := range answer.Data {
		updates[item.Name] = item.UpdateAvailable
	}

	return updates, nil
}
