// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package sysproxy

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRegistry struct {
	values   map[string]RegValue
	writeErr map[string]error // by value name
}

func newFakeRegistry() *fakeRegistry { return &fakeRegistry{values: map[string]RegValue{}} }

func regKey(key, name string) string { return key + "|" + name }

func (r *fakeRegistry) Read(key, name string) (*RegValue, error) {
	v, ok := r.values[regKey(key, name)]
	if !ok {
		return nil, nil
	}
	return &v, nil
}

func (r *fakeRegistry) Write(key, name string, v RegValue) error {
	if err := r.writeErr[name]; err != nil {
		return err
	}
	r.values[regKey(key, name)] = v
	return nil
}

func (r *fakeRegistry) Delete(key, name string) error {
	delete(r.values, regKey(key, name))
	return nil
}

func (r *fakeRegistry) inet(name string) *RegValue {
	v, _ := r.Read(windowsInternetSettingsKey, name)
	return v
}

type windowsRig struct {
	reg        *fakeRegistry
	refreshes  int
	refreshErr error
	openPorts  map[int]bool
	manager    *Manager
	path       string
}

func newWindowsRig(t *testing.T) *windowsRig {
	t.Helper()
	rig := &windowsRig{reg: newFakeRegistry(), openPorts: map[int]bool{}}
	rig.reg.values[regKey(windowsInternetSettingsKey, "ProxyEnable")] = RegValue{Type: regDword, Data: "0"}
	rig.reg.values[regKey(windowsInternetSettingsKey, "ProxyServer")] = RegValue{Type: regString, Data: "corp:3128"}
	rig.reg.values[regKey(windowsInternetSettingsKey, "ProxyOverride")] = RegValue{Type: regString, Data: "*.corp;<local>"}
	backend := newWindowsBackend(rig.reg,
		func() error { rig.refreshes++; return rig.refreshErr },
		func(port int) bool { return rig.openPorts[port] })
	rig.path = filepath.Join(t.TempDir(), "lease.json")
	rig.manager = NewManager(backend, rig.path)
	return rig
}

func TestWindowsAcquirePointsInternetSettingsAtTheEndpointAndReleaseRestoresTheExactValues(t *testing.T) {
	rig := newWindowsRig(t)

	res, err := rig.manager.Acquire(testEndpoints)
	mustAction(t, res, err, ActionAcquired)
	if got := rig.reg.inet("ProxyServer"); got == nil || got.Data != "http=127.0.0.1:10809;https=127.0.0.1:10809" {
		t.Fatalf("ProxyServer = %+v", got)
	}
	if got := rig.reg.inet("ProxyEnable"); got == nil || got.Data != "1" {
		t.Fatalf("ProxyEnable = %+v", got)
	}
	override := rig.reg.inet("ProxyOverride").Data
	for _, want := range []string{"*.corp", "<local>", "localhost", "127.*", "[::1]"} {
		if !strings.Contains(override, want) {
			t.Fatalf("the bypass list lost %q: %s", want, override)
		}
	}
	if strings.Count(strings.ToLower(override), "<local>") != 1 {
		t.Fatalf("an entry must not be listed twice: %s", override)
	}

	res, err = rig.manager.Release()
	mustAction(t, res, err, ActionReleased)
	if rig.reg.inet("ProxyServer").Data != "corp:3128" || rig.reg.inet("ProxyEnable").Data != "0" ||
		rig.reg.inet("ProxyOverride").Data != "*.corp;<local>" {
		t.Fatalf("the user's values must come back: %+v", rig.reg.values)
	}
	if v, _ := rig.reg.Read(windowsMarkerKey, windowsMarkerValue); v != nil {
		t.Fatal("the marker must be gone after release")
	}
}

func TestWindowsRestoreDeletesAValueTheUserNeverHad(t *testing.T) {
	rig := newWindowsRig(t)
	_ = rig.reg.Delete(windowsInternetSettingsKey, "ProxyOverride")

	if _, err := rig.manager.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.manager.Release(); err != nil {
		t.Fatal(err)
	}
	if rig.reg.inet("ProxyOverride") != nil {
		t.Fatal("a value that did not exist must not appear")
	}
}

func TestWindowsReleaseNeverOverwritesAProxyChangedOutsideSkipi(t *testing.T) {
	rig := newWindowsRig(t)
	if _, err := rig.manager.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	// Someone else took the proxy over: our marker is gone.
	_ = rig.reg.Delete(windowsMarkerKey, windowsMarkerValue)
	rig.reg.values[regKey(windowsInternetSettingsKey, "ProxyServer")] = RegValue{Type: regString, Data: "other:1"}

	res, err := rig.manager.Release()
	mustAction(t, res, err, ActionSkippedNotOwner)
	if rig.reg.inet("ProxyServer").Data != "other:1" {
		t.Fatal("a foreign proxy must stay")
	}
}

func TestWindowsAStaleLeaseWithoutOurMarkerIsDiscardedWithoutTouchingTheProxy(t *testing.T) {
	rig := newWindowsRig(t)
	if _, err := rig.manager.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	_ = rig.reg.Delete(windowsMarkerKey, windowsMarkerValue)
	before := rig.reg.inet("ProxyServer").Data

	res, err := rig.manager.Recover()
	mustAction(t, res, err, ActionSkippedNotOwner)
	if rig.reg.inet("ProxyServer").Data != before {
		t.Fatal("the proxy must not be touched")
	}
}

func TestWindowsAFailedWriteRollsBackToTheOriginalValues(t *testing.T) {
	rig := newWindowsRig(t)
	failing := &countingRegistry{fakeRegistry: rig.reg, failOn: func(name string, v RegValue) bool {
		return name == "ProxyOverride" && strings.Contains(v.Data, "127.*") // our write; the rollback writes the user's value
	}}
	rig.manager = NewManager(newWindowsBackend(failing, func() error { return nil }, func(int) bool { return false }), rig.path)

	if _, err := rig.manager.Acquire(testEndpoints); err == nil {
		t.Fatal("the failed write must fail the acquire")
	}
	if rig.reg.inet("ProxyServer").Data != "corp:3128" || rig.reg.inet("ProxyEnable").Data != "0" {
		t.Fatalf("the original values must be back: %+v", rig.reg.values)
	}
}

type countingRegistry struct {
	*fakeRegistry
	failOn func(name string, v RegValue) bool
}

func (r *countingRegistry) Write(key, name string, v RegValue) error {
	if r.failOn(name, v) {
		return errors.New("access denied")
	}
	return r.fakeRegistry.Write(key, name, v)
}

func TestWindowsAFailedRefreshKeepsTheLeaseSoTheProxyStaysRecoverable(t *testing.T) {
	rig := newWindowsRig(t)
	rig.refreshErr = errors.New("wininet refused")

	if _, err := rig.manager.Acquire(testEndpoints); err == nil {
		t.Fatal("a refresh failure must fail the acquire")
	}
}

func TestWindowsForceClearReportsAFailedWriteInsteadOfSuccess(t *testing.T) {
	rig := newWindowsRig(t)
	rig.reg.writeErr = map[string]error{"ProxyEnable": errors.New("access denied")}

	if err := rig.manager.ForceClear(); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("the failure must be reported, got %v", err)
	}
}

func TestWindowsForceClearSwitchesTheProxyOffAndRefreshes(t *testing.T) {
	rig := newWindowsRig(t)
	if _, err := rig.manager.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	before := rig.refreshes
	if err := rig.manager.ForceClear(); err != nil {
		t.Fatal(err)
	}
	if rig.reg.inet("ProxyEnable").Data != "0" || rig.refreshes == before {
		t.Fatal("ProxyEnable must be 0 and WinINet told")
	}
}

func TestWindowsAcquiringAnotherPortRepointsTheLeaseAndKeepsTheOriginalSnapshot(t *testing.T) {
	rig := newWindowsRig(t)
	if _, err := rig.manager.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	moved := Endpoints{Host: "127.0.0.1", HTTPPort: 20809, SocksPort: 20808}

	res, err := rig.manager.Acquire(moved)
	mustAction(t, res, err, ActionAcquired)
	if !strings.Contains(rig.reg.inet("ProxyServer").Data, "20809") {
		t.Fatalf("not repointed: %+v", rig.reg.inet("ProxyServer"))
	}
	if _, err := rig.manager.Release(); err != nil {
		t.Fatal(err)
	}
	if rig.reg.inet("ProxyServer").Data != "corp:3128" {
		t.Fatal("the snapshot must stay the user's")
	}
}

func TestWindowsAProxyServerValueRewrittenToTheSameEndpointIsStillOurs(t *testing.T) {
	rig := newWindowsRig(t)
	if _, err := rig.manager.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	// WinINet turns "http=H:P;https=H:P" into "H:P" when it refreshes.
	rig.reg.values[regKey(windowsInternetSettingsKey, "ProxyServer")] = RegValue{Type: regString, Data: "127.0.0.1:10809"}

	res, err := rig.manager.Acquire(testEndpoints)
	mustAction(t, res, err, ActionAlreadyAcquired)
	res, err = rig.manager.Release()
	mustAction(t, res, err, ActionReleased)
	if rig.reg.inet("ProxyServer").Data != "corp:3128" {
		t.Fatal("must restore")
	}
}

func TestWindowsADeadLoopbackProxyIsNotRestoredAsTheOriginalSetting(t *testing.T) {
	rig := newWindowsRig(t)
	// What an earlier session of ours left behind.
	rig.reg.values[regKey(windowsInternetSettingsKey, "ProxyEnable")] = RegValue{Type: regDword, Data: "1"}
	rig.reg.values[regKey(windowsInternetSettingsKey, "ProxyServer")] = RegValue{Type: regString, Data: "127.0.0.1:55555"}

	if _, err := rig.manager.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.manager.Release(); err != nil {
		t.Fatal(err)
	}
	if rig.reg.inet("ProxyEnable").Data != "0" {
		t.Fatal("a dead proxy must come back disabled")
	}
}

func TestWindowsALiveLoopbackProxyOfAnotherToolIsRestoredAsTheOriginalSetting(t *testing.T) {
	rig := newWindowsRig(t)
	rig.reg.values[regKey(windowsInternetSettingsKey, "ProxyEnable")] = RegValue{Type: regDword, Data: "1"}
	rig.reg.values[regKey(windowsInternetSettingsKey, "ProxyServer")] = RegValue{Type: regString, Data: "127.0.0.1:8888"}
	rig.openPorts[8888] = true

	if _, err := rig.manager.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.manager.Release(); err != nil {
		t.Fatal(err)
	}
	if rig.reg.inet("ProxyEnable").Data != "1" {
		t.Fatal("a live proxy of another tool is the user's setting")
	}
}

func TestWindowsRepairSwitchesOffAnEnabledProxyThatPointsAtADeadLoopbackPort(t *testing.T) {
	rig := newWindowsRig(t)
	rig.reg.values[regKey(windowsInternetSettingsKey, "ProxyEnable")] = RegValue{Type: regDword, Data: "1"}
	rig.reg.values[regKey(windowsInternetSettingsKey, "ProxyServer")] = RegValue{Type: regString, Data: "http=127.0.0.1:55555;https=127.0.0.1:55555"}

	changed, err := rig.manager.RepairStale()
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if rig.reg.inet("ProxyEnable").Data != "0" || rig.refreshes == 0 {
		t.Fatal("must be switched off and refreshed")
	}
}

func TestWindowsRepairLeavesLiveRemoteAndOurOwnProxiesAlone(t *testing.T) {
	rig := newWindowsRig(t)
	cases := map[string]func(){
		"live":   func() { rig.openPorts[8888] = true; rig.setProxy("127.0.0.1:8888") },
		"remote": func() { rig.setProxy("corp:3128") },
	}
	for name, setup := range cases {
		setup()
		changed, err := rig.manager.RepairStale()
		if err != nil || changed {
			t.Fatalf("%s: changed=%v err=%v", name, changed, err)
		}
	}
	// Our own live session's proxy: a lease with a marker.
	rig.setProxy("corp:3128")
	if _, err := rig.manager.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	rig.openPorts[10809] = false
	changed, err := rig.manager.RepairStale()
	if err != nil || changed {
		t.Fatalf("our own proxy must stay: changed=%v err=%v", changed, err)
	}
}

func (r *windowsRig) setProxy(server string) {
	r.reg.values[regKey(windowsInternetSettingsKey, "ProxyEnable")] = RegValue{Type: regDword, Data: "1"}
	r.reg.values[regKey(windowsInternetSettingsKey, "ProxyServer")] = RegValue{Type: regString, Data: server}
}

func TestWindowsAForeignMarkerBlocksAnAcquire(t *testing.T) {
	rig := newWindowsRig(t)
	rig.reg.values[regKey(windowsMarkerKey, windowsMarkerValue)] = RegValue{Type: regString, Data: "someone-else"}

	if _, err := rig.manager.Acquire(testEndpoints); err == nil || !strings.Contains(err.Error(), "marker") {
		t.Fatalf("got %v", err)
	}
}
