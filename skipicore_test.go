package skipicore

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCoreVersion(t *testing.T) {
	v := CoreVersion()
	if v == "" {
		t.Fatal("expected non-empty core version")
	}
	t.Logf("Core version: %s", v)
}

func TestInitCoreEnv(t *testing.T) {
	InitCoreEnv("/tmp/assets", "testkey123")
}

func TestStartAndStopLoop(t *testing.T) {
	// Allocate a random port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	configJSON := fmt.Sprintf(`{
		"log": {
			"loglevel": "none"
		},
		"inbounds": [
			{
				"port": %d,
				"listen": "127.0.0.1",
				"protocol": "socks",
				"settings": {
					"auth": "noauth",
					"udp": false
				}
			}
		],
		"outbounds": [
			{
				"protocol": "freedom"
			}
		]
	}`, port)

	ctrl := NewCoreController(nil)
	if err := ctrl.StartLoop(configJSON, 0); err != nil {
		t.Fatalf("StartLoop failed: %v", err)
	}

	if !ctrl.IsRunning() {
		t.Fatal("expected controller to be running")
	}

	if err := ctrl.StopLoop(); err != nil {
		t.Fatalf("StopLoop failed: %v", err)
	}

	if ctrl.IsRunning() {
		t.Fatal("expected controller to not be running")
	}
}

func TestMeasureOutboundDelay(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	configJSON := `{
		"log": {
			"loglevel": "none"
		},
		"outbounds": [
			{
				"protocol": "freedom",
				"tag": "direct"
			}
		]
	}`

	delay, err := MeasureOutboundDelay(configJSON, ts.URL)
	if err != nil {
		t.Fatalf("MeasureOutboundDelay failed: %v", err)
	}
	if delay < 0 {
		t.Fatalf("expected non-negative delay, got %d", delay)
	}
	t.Logf("Measured delay to local test server: %d ms", delay)
}
