package route

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/codegen"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/config"
)

type noScans struct{}

func (noScans) Status() codegen.Status     { return codegen.Status{} }
func (noScans) Apps() []codegen.AppSummary { return []codegen.AppSummary{} }
func (noScans) Start() bool                { return true }
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
	request := httptest.NewRequest(method, path, nil)
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
