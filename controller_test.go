package skipicore

import (
	"fmt"
	"github.com/ZloyRadetski/skipi-core/internal/trafficstats"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestStartAndStopLoop(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

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
				"protocol": "freedom",
				"tag": "direct"
			}
		]
	}`, port)

	ctrl := NewCoreController(&dummyCallbackHandler{})
	ctrl.RegisterProcessFinder(&dummyProcessFinder{})

	if err := ctrl.StartLoop(configJSON, 0); err != nil {
		t.Fatalf("StartLoop failed: %v", err)
	}

	if !ctrl.IsRunning() {
		t.Fatal("expected controller to be running")
	}

	// Test active connection delay measurement
	delay, err := ctrl.MeasureDelay(ts.URL)
	if err != nil {
		t.Fatalf("MeasureDelay failed on running instance: %v", err)
	}
	if delay < 0 {
		t.Fatalf("expected non-negative delay, got %d", delay)
	}
	t.Logf("Active instance MeasureDelay: %d ms", delay)

	// Test querying traffic stats
	_ = ctrl.QueryAllOutboundTrafficStats()

	if err := ctrl.StopLoop(); err != nil {
		t.Fatalf("StopLoop failed: %v", err)
	}

	if ctrl.IsRunning() {
		t.Fatal("expected controller to not be running")
	}
}

func TestQueryTrafficStatsReturnsStructuredEmptySnapshotWhenStopped(t *testing.T) {
	controller := NewCoreController(nil)
	if got := controller.QueryTrafficStats(); got != trafficstats.EmptySnapshotJSON {
		t.Fatalf("unexpected stopped-core stats snapshot: %s", got)
	}
}

func TestStartLoopPublishesAndStopLoopClearsTunFdEnv(t *testing.T) {
	unsetEnvVariable(tunFdKey)
	unsetEnvVariable(v2rayTunFdKey)

	configJSON := `{
		"log": { "loglevel": "none" },
		"outbounds": [
			{ "protocol": "freedom", "tag": "direct" }
		]
	}`

	ctrl := NewCoreController(&dummyCallbackHandler{})
	if err := ctrl.StartLoop(configJSON, 12345); err != nil {
		t.Fatalf("StartLoop failed: %v", err)
	}

	if got := os.Getenv(tunFdKey); got != "12345" {
		t.Fatalf("expected %s=12345 while running, got %q", tunFdKey, got)
	}
	if got := os.Getenv(v2rayTunFdKey); got != "12345" {
		t.Fatalf("expected %s=12345 while running, got %q", v2rayTunFdKey, got)
	}

	if err := ctrl.StopLoop(); err != nil {
		t.Fatalf("StopLoop failed: %v", err)
	}

	if got := os.Getenv(tunFdKey); got != "" {
		t.Fatalf("expected %s cleared after StopLoop, got %q", tunFdKey, got)
	}
	if got := os.Getenv(v2rayTunFdKey); got != "" {
		t.Fatalf("expected %s cleared after StopLoop, got %q", v2rayTunFdKey, got)
	}
}

func TestStartLoopFailureDoesNotTouchTunFdEnv(t *testing.T) {
	unsetEnvVariable(tunFdKey)
	unsetEnvVariable(v2rayTunFdKey)

	ctrl := NewCoreController(&dummyCallbackHandler{})
	if err := ctrl.StartLoop("{not valid json", 5555); err == nil {
		t.Fatal("expected StartLoop to fail on invalid config")
	}

	if got := os.Getenv(tunFdKey); got != "" {
		t.Fatalf("failed start must not publish %s, got %q", tunFdKey, got)
	}
	if got := os.Getenv(v2rayTunFdKey); got != "" {
		t.Fatalf("failed start must not publish %s, got %q", v2rayTunFdKey, got)
	}
}

// A start that fails after some inbounds are already listening must give those listeners back,
// otherwise every retry reports "address already in use" until the process exits.
func TestStartLoopFailureReleasesListenersAndTunFdEnv(t *testing.T) {
	unsetEnvVariable(tunFdKey)
	unsetEnvVariable(v2rayTunFdKey)

	freePort := reserveLocalPort(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port

	configJSON := fmt.Sprintf(`{
		"log": { "loglevel": "none" },
		"inbounds": [
			{ "listen": "127.0.0.1", "port": %d, "protocol": "socks", "settings": { "auth": "noauth" } },
			{ "listen": "127.0.0.1", "port": %d, "protocol": "socks", "settings": { "auth": "noauth" } }
		],
		"outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
	}`, freePort, busyPort)

	ctrl := NewCoreController(&dummyCallbackHandler{})
	if err := ctrl.StartLoop(configJSON, 7777); err == nil {
		t.Fatal("expected StartLoop to fail because one inbound port is taken")
	}

	if ctrl.IsRunning() {
		t.Fatal("a failed start must not leave the controller running")
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", freePort))
	if err != nil {
		t.Fatalf("the inbound that did start was not released: %v", err)
	}
	_ = listener.Close()
	if got := os.Getenv(tunFdKey); got != "" {
		t.Fatalf("failed start must not leave %s set, got %q", tunFdKey, got)
	}
	if got := os.Getenv(v2rayTunFdKey); got != "" {
		t.Fatalf("failed start must not leave %s set, got %q", v2rayTunFdKey, got)
	}
}
