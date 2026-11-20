// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package desktopbridge

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ZloyRadetski/skipi-core/desktop/sysproxy"
)

// recordingBackend is a system proxy that keeps one string.
type recordingBackend struct{ state string }

func (b *recordingBackend) Supported() bool { return true }
func (b *recordingBackend) Capture() (json.RawMessage, error) {
	return json.Marshal(b.state)
}
func (b *recordingBackend) Apply(l sysproxy.Lease) error {
	b.state = "ours:" + l.Endpoints.Host
	return nil
}
func (b *recordingBackend) Ownership(sysproxy.Lease) (sysproxy.Ownership, error) {
	return sysproxy.Active, nil
}
func (b *recordingBackend) Restore(l sysproxy.Lease) error {
	return json.Unmarshal(l.Snapshot, &b.state)
}
func (b *recordingBackend) Discard(sysproxy.Lease) error { return nil }
func (b *recordingBackend) ForceClear() error            { b.state = "off"; return nil }
func (b *recordingBackend) RepairStale() (bool, error)   { return true, nil }

func runtimeWithSystemProxy(t *testing.T) (*Runtime, *recordingBackend) {
	t.Helper()
	backend := &recordingBackend{state: "user"}
	runtime := NewRuntime()
	runtime.newSystemProxy = func(dir string) *sysproxy.Manager {
		return sysproxy.NewManager(backend, dir+"/lease.json")
	}
	if _, err := runtime.SystemProxy("configure", `{"directory":"`+strings.ReplaceAll(t.TempDir(), `\`, `/`)+`"}`); err != nil {
		t.Fatal(err)
	}
	return runtime, backend
}

func TestSystemProxyRefusesEveryOperationBeforeItIsConfigured(t *testing.T) {
	runtime := NewRuntime()
	if _, err := runtime.SystemProxy("acquire", `{"host":"127.0.0.1","httpPort":1,"socksPort":2}`); err == nil ||
		!strings.Contains(err.Error(), "not configured") {
		t.Fatalf("got %v", err)
	}
}

func TestSystemProxyAcquiresAndReleasesThroughJson(t *testing.T) {
	runtime, backend := runtimeWithSystemProxy(t)

	out, err := runtime.SystemProxy("acquire", `{"host":"127.0.0.1","httpPort":10809,"socksPort":10808}`)
	if err != nil || out != `{"action":"acquired"}` {
		t.Fatalf("acquire: %q %v", out, err)
	}
	if backend.state != "ours:127.0.0.1" {
		t.Fatalf("state = %q", backend.state)
	}

	out, err = runtime.SystemProxy("release", "")
	if err != nil || out != `{"action":"released"}` {
		t.Fatalf("release: %q %v", out, err)
	}
	if backend.state != "user" {
		t.Fatalf("the user's value must come back: %q", backend.state)
	}
}

func TestSystemProxyReportsSupportRecoveryRepairAndForceClear(t *testing.T) {
	runtime, backend := runtimeWithSystemProxy(t)

	if out, err := runtime.SystemProxy("supported", ""); err != nil || out != `{"supported":true}` {
		t.Fatalf("supported: %q %v", out, err)
	}
	if out, err := runtime.SystemProxy("recover", ""); err != nil || out != `{"action":"nothingToRelease"}` {
		t.Fatalf("recover: %q %v", out, err)
	}
	if out, err := runtime.SystemProxy("repairStale", ""); err != nil || out != `{"changed":true}` {
		t.Fatalf("repairStale: %q %v", out, err)
	}
	if out, err := runtime.SystemProxy("forceClear", ""); err != nil || out != `{}` {
		t.Fatalf("forceClear: %q %v", out, err)
	}
	if backend.state != "off" {
		t.Fatalf("state = %q", backend.state)
	}
}

func TestSystemProxyRefusesANonLoopbackEndpointAndAnUnknownOperation(t *testing.T) {
	runtime, _ := runtimeWithSystemProxy(t)

	if _, err := runtime.SystemProxy("acquire", `{"host":"8.8.8.8","httpPort":1,"socksPort":2}`); err == nil {
		t.Fatal("only loopback may be published")
	}
	if _, err := runtime.SystemProxy("acquire", `not json`); err == nil {
		t.Fatal("malformed arguments must fail")
	}
	if _, err := runtime.SystemProxy("explode", ""); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("got %v", err)
	}
}

func TestSystemProxyConfigureNeedsADirectory(t *testing.T) {
	runtime := NewRuntime()
	if _, err := runtime.SystemProxy("configure", `{}`); err == nil {
		t.Fatal("a lease needs somewhere to live")
	}
}
