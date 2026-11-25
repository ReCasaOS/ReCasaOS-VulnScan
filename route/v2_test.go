package route

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/codegen"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/config"
	v2Route "github.com/ReCasaOS/ReCasaOS-VulnScan/route/v2"
)

type noScans struct{}

func (noScans) Status() codegen.Status     { return codegen.Status{} }
func (noScans) Apps() []codegen.AppSummary { return []codegen.AppSummary{} }
func (noScans) Start() bool                { return true }
func (noScans) Compare(context.Context, string, string) codegen.Comparison {
	return codegen.Comparison{Verdict: codegen.NotWorse, Added: []codegen.Finding{}}
}
func (noScans) App(name string) (codegen.AppDetail, bool) {
	return codegen.AppDetail{App: name, Images: []codegen.ImageFindings{}}, true
}

var everyRoute = []struct{ method, path string }{
	{http.MethodGet, "/v2/vuln_scan/status"},
	{http.MethodGet, "/v2/vuln_scan/apps"},
	{http.MethodGet, "/v2/vuln_scan/apps/nextcloud"},
	{http.MethodPost, "/v2/vuln_scan/scan"},
}

// The common library keeps user-service's public key for ten seconds whatever the runtime
// path, so every test of this binary signs with the same key, served by the same stand-in.
var signer = sync.OnceValues(func() (address string, sign func() (string, error)) {
	privateKey, publicKey, err := jwt.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	jwks, err := jwt.GenerateJwksJSON(publicKey)
	if err != nil {
		panic(err)
	}

	return httptest.NewServer(jwt.JWKSHandler(jwks)).URL, func() (string, error) { return jwt.GetAccessToken("someone", privateKey, 1) }
})

// box is a runtime path with an internal secret and a user-service that signs tokens; it
// returns a valid token of account 1. The role of that account is what the test says.
func box(t *testing.T, role string, known bool) (token string) {
	t.Helper()
	logger.LogInitConsoleOnly()
	runtime := t.TempDir()
	previous := config.CommonInfo.RuntimePath
	config.CommonInfo.RuntimePath = runtime
	previousAccount := account
	account = func(string, string) (string, bool, bool) { return role, false, known }
	t.Cleanup(func() { config.CommonInfo.RuntimePath = previous; account = previousAccount })

	if err := os.WriteFile(filepath.Join(runtime, external.InternalSecretFilename), []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	address, sign := signer()
	if err := os.WriteFile(filepath.Join(runtime, external.UserServiceAddressFilename), []byte(address), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := sign()
	if err != nil {
		t.Fatal(err)
	}

	return token
}

func answer(method, path, authorization, remote string) int {
	return answerWith(method, path, authorization, remote, "")
}

func answerWith(method, path, authorization, remote, body string) int {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = remote
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	InitV2Router(noScans{}).ServeHTTP(recorder, request)

	return recorder.Code
}

func TestRoutesRefuseNoToken(t *testing.T) {
	box(t, "admin", true)
	for _, r := range everyRoute {
		if code := answer(r.method, r.path, "", "203.0.113.5:40000"); code != http.StatusUnauthorized {
			t.Errorf("%s %s: %d, want 401", r.method, r.path, code)
		}
	}
}

func TestRoutesRefuseNonOwner(t *testing.T) {
	token := box(t, "user", true)
	for _, r := range everyRoute {
		if code := answer(r.method, r.path, token, "203.0.113.5:40000"); code != http.StatusForbidden {
			t.Errorf("%s %s: %d, want 403", r.method, r.path, code)
		}
	}
}

func TestRoutesRefuseUnknownRole(t *testing.T) {
	token := box(t, "user", false)
	for _, r := range everyRoute {
		if code := answer(r.method, r.path, token, "203.0.113.5:40000"); code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: %d, want 503", r.method, r.path, code)
		}
	}
}

func TestRoutesAcceptOwner(t *testing.T) {
	token := box(t, "admin", true)
	for _, r := range everyRoute {
		if code := answer(r.method, r.path, token, "203.0.113.5:40000"); code/100 != 2 {
			t.Errorf("%s %s: %d, want 2xx", r.method, r.path, code)
		}
	}
}

func TestRoutesAcceptInternal(t *testing.T) {
	box(t, "user", true)
	for _, r := range everyRoute {
		if code := answer(r.method, r.path, "Internal s3cret", "127.0.0.1:40000"); code/100 != 2 {
			t.Errorf("%s %s: %d, want 2xx", r.method, r.path, code)
		}
	}
}

// The token is read from the header only: a route that took ?token= would leave it in logs.
func TestRoutesRefuseTokenInQuery(t *testing.T) {
	token := box(t, "admin", true)
	for _, r := range everyRoute {
		if code := answer(r.method, r.path+"?token="+token, "", "203.0.113.5:40000"); code != http.StatusUnauthorized {
			t.Errorf("%s %s: %d, want 401", r.method, r.path, code)
		}
	}
}

type scansStub struct {
	noScans
	running bool
}

func (s scansStub) Start() bool { return !s.running }
func (scansStub) App(name string) (codegen.AppDetail, bool) {
	return codegen.AppDetail{}, false
}
func (scansStub) Apps() []codegen.AppSummary {
	return []codegen.AppSummary{{App: "vaultwarden", Critical: 4, High: 117, Actionable: true}}
}

func ask(t *testing.T, scans v2Route.Scans, method, path string) (int, string) {
	t.Helper()
	return askWith(t, scans, method, path, "")
}

func askWith(t *testing.T, scans v2Route.Scans, method, path, body string) (int, string) {
	t.Helper()
	box(t, "user", true)
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "127.0.0.1:40000"
	request.Header.Set("Authorization", "Internal s3cret")
	recorder := httptest.NewRecorder()
	InitV2Router(scans).ServeHTTP(recorder, request)

	return recorder.Code, strings.TrimSpace(recorder.Body.String())
}

func TestStartScanConflict(t *testing.T) {
	if code, _ := ask(t, scansStub{running: true}, http.MethodPost, "/v2/vuln_scan/scan"); code != http.StatusConflict {
		t.Fatalf("%d, want 409", code)
	}
}

func TestStartScanAccepted(t *testing.T) {
	if code, _ := ask(t, scansStub{}, http.MethodPost, "/v2/vuln_scan/scan"); code != http.StatusAccepted {
		t.Fatalf("%d, want 202", code)
	}
}

func TestGetAppUnknown(t *testing.T) {
	if code, _ := ask(t, scansStub{}, http.MethodGet, "/v2/vuln_scan/apps/nothing"); code != http.StatusNotFound {
		t.Fatalf("%d, want 404", code)
	}
}

// The words of the API, as the dashboard reads them.
func TestAppsShape(t *testing.T) {
	code, body := ask(t, scansStub{}, http.MethodGet, "/v2/vuln_scan/apps")
	want := `{"data":[{"actionable":true,"app":"vaultwarden","critical":4,"high":117,"loose":false,"os_only":false,"skipped":""}]}`
	if code != http.StatusOK || body != want {
		t.Fatalf("%d %s\nwant %s", code, body, want)
	}
}

func TestStatusShape(t *testing.T) {
	code, body := ask(t, scansStub{}, http.MethodGet, "/v2/vuln_scan/status")
	if want := `{"data":{"last_error":"","running":false}}`; code != http.StatusOK || body != want {
		t.Fatalf("%d %s\nwant %s", code, body, want)
	}
}

const compareBody = `{"current":"sha256:1","candidate":"sha256:2"}`

// A body-less POST to the other routes is fine, so the compare route is checked on its own.
func TestCompareRouteNeedsOwnerOrInternal(t *testing.T) {
	const path = "/v2/vuln_scan/compare"
	token := box(t, "admin", true)
	if code := answerWith(http.MethodPost, path, "", "203.0.113.5:40000", compareBody); code != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", code)
	}
	if code := answerWith(http.MethodPost, path, token, "203.0.113.5:40000", compareBody); code != http.StatusOK {
		t.Errorf("owner: %d, want 200", code)
	}
	token = box(t, "user", true)
	if code := answerWith(http.MethodPost, path, token, "203.0.113.5:40000", compareBody); code != http.StatusForbidden {
		t.Errorf("non-admin: %d, want 403", code)
	}
	if code := answerWith(http.MethodPost, path, "Internal s3cret", "127.0.0.1:40000", compareBody); code != http.StatusOK {
		t.Errorf("internal: %d, want 200", code)
	}
}

func TestCompareRouteRefusesEmptyBody(t *testing.T) {
	for _, body := range []string{``, `{}`, `{"current":"a"}`, `{"candidate":"b"}`, `{"current":"","candidate":"b"}`, `{"current":"a","candidate":""}`} {
		if code, _ := askWith(t, noScans{}, http.MethodPost, "/v2/vuln_scan/compare", body); code != http.StatusBadRequest {
			t.Errorf("%q: %d, want 400", body, code)
		}
	}
}

func TestCompareShape(t *testing.T) {
	code, body := askWith(t, noScans{}, http.MethodPost, "/v2/vuln_scan/compare", compareBody)
	want := `{"data":{"added":[],"candidate_critical":0,"current_critical":0,"reason":"","verdict":"not_worse"}}`
	if code != http.StatusOK || body != want {
		t.Fatalf("%d %s\nwant %s", code, body, want)
	}
}

type ctxStub struct {
	noScans
	got *context.Context
}

func (s ctxStub) Compare(ctx context.Context, _, _ string) codegen.Comparison {
	*s.got = ctx
	return codegen.Comparison{Verdict: codegen.NotWorse, Added: []codegen.Finding{}}
}

// A caller who hangs up must stop the scan: the handler hands on the request's context.
func TestCompareRoutePassesTheRequestContext(t *testing.T) {
	box(t, "user", true)
	var got context.Context
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "/v2/vuln_scan/compare", strings.NewReader(compareBody)).WithContext(cancelled)
	request.RemoteAddr = "127.0.0.1:40000"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Internal s3cret")
	InitV2Router(ctxStub{got: &got}).ServeHTTP(httptest.NewRecorder(), request)

	if got == nil || got.Err() == nil {
		t.Fatalf("the context given to Compare is %v, want the request's, cancelled", got)
	}
}
