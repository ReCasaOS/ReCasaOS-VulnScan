package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/common"
)

// Events publishes to the message bus over its unix socket.
type Events struct {
	RuntimePath string
}

type eventTypeJSON struct {
	SourceID         string             `json:"sourceID"`
	Name             string             `json:"name"`
	PropertyTypeList []propertyTypeJSON `json:"propertyTypeList"`
}

type propertyTypeJSON struct {
	Name string `json:"name"`
}

// Register makes EventFound discoverable on the message bus, which the core's alerts
// subscribe to. Registering it again after a restart is answered 409, which is fine.
func (e Events) Register(ctx context.Context) error {
	payload, err := json.Marshal([]eventTypeJSON{{
		SourceID: common.ServiceName, Name: EventFound,
		PropertyTypeList: []propertyTypeJSON{{Name: "apps"}, {Name: "count"}},
	}})
	if err != nil {
		return err
	}

	socketPath := external.MessageBusSocketPath(e.RuntimePath)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v2/message_bus/event_type", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("message bus answered %s: %s", resp.Status, msg)
	}

	return nil
}

// Publish sends an event.
func (e Events) Publish(name string, properties map[string]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := external.PublishEventInSocket(ctx, e.RuntimePath, common.ServiceName, name, properties)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("message bus answered %s to %s", resp.Status, name)
	}

	return nil
}
