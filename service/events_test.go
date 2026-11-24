package service

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ReCasaOS/CasaOS-Common/external"
)

// What the bus is told: the core's alerts look the event up by this source and this name.
func TestRegisterDeclaresTheEvent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a unix socket where the message bus has its own")
	}
	runtimePath := t.TempDir()
	socket := external.MessageBusSocketPath(runtimePath)
	if err := os.MkdirAll(filepath.Dir(socket), 0o755); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var path, body string
	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, _ := io.ReadAll(r.Body)
			path, body = r.Method+" "+r.URL.Path, string(data)
			w.WriteHeader(http.StatusConflict) // registered before the restart: fine
		}))
	}()

	if err := (Events{RuntimePath: runtimePath}).Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := `[{"sourceID":"vuln-scan","name":"vuln:found","propertyTypeList":[{"name":"apps"},{"name":"count"}]}]`
	if path != "POST /v2/message_bus/event_type" || body != want {
		t.Fatalf("%s %s\nwant %s", path, body, want)
	}
}
