package service

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"

	"github.com/ReCasaOS/CasaOS-Common/external"
)

// What the bus is told: the core's alerts look each event up by this source and this name.
// A type registered before the restart is answered 409, and the other one is still sent.
func TestRegisterSendsBothEventTypes(t *testing.T) {
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

	var mu sync.Mutex
	var requests []string
	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, _ := io.ReadAll(r.Body)
			mu.Lock()
			requests = append(requests, r.Method+" "+r.URL.Path+" "+string(data))
			first := len(requests) == 1
			mu.Unlock()
			if first {
				w.WriteHeader(http.StatusConflict) // registered before the restart: fine
			}
		}))
	}()

	if err := (Events{RuntimePath: runtimePath}).Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`POST /v2/message_bus/event_type [{"sourceID":"vuln-scan","name":"vuln:found","propertyTypeList":[{"name":"apps"},{"name":"count"}]}]`,
		`POST /v2/message_bus/event_type [{"sourceID":"vuln-scan","name":"vuln:exploited","propertyTypeList":[{"name":"apps"},{"name":"count"}]}]`,
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("%q, want %q", requests, want)
	}
}
