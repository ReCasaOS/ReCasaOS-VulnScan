package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/trivy"
)

func finding(severity, id, pkg string) trivy.Finding {
	return trivy.Finding{ID: id, Package: pkg, Installed: "1", Fixed: "2", Severity: severity}
}

var at = time.Date(2026, 11, 24, 5, 30, 0, 0, time.UTC)

func TestSummariesCounts(t *testing.T) {
	images := []Image{{ID: "sha256:1", Apps: []string{"app"}}, {ID: "sha256:2", Apps: []string{"app"}}}
	state := State{Images: map[string]ImageResult{
		"sha256:1": {ScannedAt: at, Findings: []trivy.Finding{finding(trivy.Critical, "CVE-1", "openssl"), finding(trivy.High, "CVE-2", "zlib")}},
		// the same vulnerability of the same package in the app's other image is one thing to fix
		"sha256:2": {ScannedAt: at.Add(time.Hour), Findings: []trivy.Finding{finding(trivy.Critical, "CVE-1", "openssl"), finding(trivy.High, "CVE-3", "zlib")}},
	}}

	want := []AppSummary{{App: "app", Critical: 1, High: 2, ScannedAt: at}}
	if got := Summaries(images, state, nil); !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v\nwant %+v", got, want)
	}
}

func TestSummariesSkippedReason(t *testing.T) {
	images := []Image{{ID: "sha256:1", Apps: []string{"b"}}, {ID: "sha256:2", Apps: []string{"b"}}, {ID: "sha256:3", Apps: []string{"a"}}}
	state := State{Images: map[string]ImageResult{
		"sha256:1": {ScannedAt: at, OSOnly: true},
		"sha256:2": {Skipped: SkippedNoRoom},
		// sha256:3 has no result yet: no scan has run since its app was installed
	}}

	want := []AppSummary{{App: "a"}, {App: "b", ScannedAt: at, Skipped: SkippedNoRoom, OSOnly: true}}
	if got := Summaries(images, state, nil); !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v\nwant %+v", got, want)
	}
}

func TestSummariesLoose(t *testing.T) {
	images := []Image{{ID: "sha256:1", Loose: []string{"byhand"}}}
	state := State{Images: map[string]ImageResult{"sha256:1": {ScannedAt: at, Findings: []trivy.Finding{finding(trivy.Critical, "CVE-1", "openssl")}}}}

	want := []AppSummary{{App: "byhand", Loose: true, Critical: 1, ScannedAt: at}}
	if got := Summaries(images, state, map[string]bool{"byhand": true}); !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v\nwant %+v", got, want)
	}
}

func TestSummariesActionable(t *testing.T) {
	images := []Image{{ID: "sha256:1", Apps: []string{"critical", "critical-no-update"}}, {ID: "sha256:2", Apps: []string{"high"}}}
	state := State{Images: map[string]ImageResult{
		"sha256:1": {ScannedAt: at, Findings: []trivy.Finding{finding(trivy.Critical, "CVE-1", "openssl")}},
		"sha256:2": {ScannedAt: at, Findings: []trivy.Finding{finding(trivy.High, "CVE-2", "zlib")}},
	}}

	got := Summaries(images, state, map[string]bool{"critical": true, "high": true})
	actionable := map[string]bool{}
	for _, summary := range got {
		actionable[summary.App] = summary.Actionable
	}
	if want := map[string]bool{"critical": true, "critical-no-update": false, "high": false}; !reflect.DeepEqual(actionable, want) {
		t.Fatalf("%v, want %v", actionable, want)
	}
}

func TestDetail(t *testing.T) {
	images := []Image{{ID: "sha256:1", Apps: []string{"app"}}, {ID: "sha256:2", Apps: []string{"other"}}, {ID: "sha256:3", Loose: []string{"byhand"}}}
	state := State{Images: map[string]ImageResult{"sha256:1": {ScannedAt: at, Findings: []trivy.Finding{finding(trivy.High, "CVE-2", "zlib")}}}}

	got, found := Detail("app", images, state)
	if want := map[string]ImageResult{"sha256:1": state.Images["sha256:1"]}; !found || !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v %v", got, found)
	}
	if got, found := Detail("byhand", images, state); !found || len(got) != 1 {
		t.Fatalf("a loose container: %+v %v", got, found)
	}
	if _, found := Detail("nothing", images, state); found {
		t.Fatal("an app that is not on the box is found")
	}
}

// appManagement stands in for AppManagement: it answers the two reads, to internal requests only.
func appManagement(t *testing.T, operations, grid string) (runtimePath string) {
	t.Helper()
	runtimePath = t.TempDir()
	mux := http.NewServeMux()
	answer := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Internal s3cret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(body))
		}
	}
	mux.HandleFunc("/v2/app_management/operations", answer(operations))
	mux.HandleFunc("/v2/app_management/web/appgrid", answer(grid))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	for name, content := range map[string]string{external.InternalSecretFilename: "s3cret", external.AppManageURLFilename: server.URL} {
		if err := os.WriteFile(filepath.Join(runtimePath, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return runtimePath
}

func TestAppManagementBusy(t *testing.T) {
	for body, want := range map[string]bool{
		`{"operations":[],"os_upgrade_open":false}`:                                    false,
		`{"operations":[{"app":"nextcloud","kind":"backup"}],"os_upgrade_open":false}`: true,
		`{"operations":[],"os_upgrade_open":true}`:                                     true,
	} {
		am := AppManagement{RuntimePath: appManagement(t, body, `{}`)}
		if busy, err := am.Busy(context.Background()); err != nil || busy != want {
			t.Errorf("%s: %v, err %v; want %v", body, busy, err, want)
		}
	}
}

func TestAppManagementUpdates(t *testing.T) {
	// an update of the same tag, a newer version of a pinned one, nothing, and never checked
	grid := `{"data":[
	 {"name":"same-tag","update_available":true},
	 {"name":"pinned","update_available":false,"newer_tags":[{"image":"postgres:16"}]},
	 {"name":"current","update_available":false},
	 {"name":"unchecked"}]}`
	am := AppManagement{RuntimePath: appManagement(t, `{}`, grid)}

	updates, err := am.Updates(context.Background())
	want := map[string]bool{"same-tag": true, "pinned": true, "current": false, "unchecked": false}
	if err != nil || !reflect.DeepEqual(updates, want) {
		t.Fatalf("%v, err %v; want %v", updates, err, want)
	}
}

func TestAppManagementDown(t *testing.T) {
	am := AppManagement{RuntimePath: t.TempDir()} // no address file: the service is not there
	if _, err := am.Busy(context.Background()); err == nil {
		t.Error("Busy: no error")
	}
	if _, err := am.Updates(context.Background()); err == nil {
		t.Error("Updates: no error")
	}
}
