// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package sysproxy

import (
	"os"
	"path/filepath"
	"testing"
)

// The leases the Kotlin host used to write. A session of the old app that ended without releasing leaves
// one behind, and the new Core must give the user's settings back from it rather than refuse to start.

const legacyWindowsLease = `{
    "phase": "Active",
    "ownerToken": "04497b13-c9c6-4ed8-bf06-cfb8d8e1b112",
    "endpoint": {
        "port": 10809
    },
    "appliedProxyOverride": "localhost;127.*;<local>",
    "snapshot": {
        "proxyEnable": {"type": "Dword", "data": "0x0"},
        "proxyServer": {"type": "String", "data": "corp:3128"},
        "proxyOverride": {"type": "String", "data": "*.corp;<local>"}
    }
}`

func TestAnOldWindowsLeaseIsRestoredFromWhereItWasLeftBehind(t *testing.T) {
	rig := newWindowsRig(t)
	if err := os.WriteFile(rig.path, []byte(legacyWindowsLease), 0o600); err != nil {
		t.Fatal(err)
	}
	// The state that old session left: its marker and its endpoint are in place.
	rig.reg.values[regKey(windowsMarkerKey, windowsMarkerValue)] = RegValue{Type: regString, Data: "04497b13-c9c6-4ed8-bf06-cfb8d8e1b112"}
	rig.reg.values[regKey(windowsInternetSettingsKey, "ProxyEnable")] = RegValue{Type: regDword, Data: "1"}
	rig.reg.values[regKey(windowsInternetSettingsKey, "ProxyServer")] = RegValue{Type: regString, Data: "http=127.0.0.1:10809;https=127.0.0.1:10809"}
	rig.reg.values[regKey(windowsInternetSettingsKey, "ProxyOverride")] = RegValue{Type: regString, Data: "localhost;127.*;<local>"}

	res, err := rig.manager.Recover()
	mustAction(t, res, err, ActionRecovered)
	if !rig.reg.inet("ProxyEnable").isDword(0) || rig.reg.inet("ProxyServer").Data != "corp:3128" ||
		rig.reg.inet("ProxyOverride").Data != "*.corp;<local>" {
		t.Fatalf("the user's values must come back: %+v", rig.reg.values)
	}
	if v, _ := rig.reg.Read(windowsMarkerKey, windowsMarkerValue); v != nil {
		t.Fatal("the old marker must be gone")
	}
	if _, err := os.Stat(rig.path); !os.IsNotExist(err) {
		t.Fatalf("the old lease must be removed: %v", err)
	}
}

func TestAnOldWindowsLeaseWhoseMarkerIsGoneIsDiscardedWithoutTouchingTheProxy(t *testing.T) {
	rig := newWindowsRig(t)
	if err := os.WriteFile(rig.path, []byte(legacyWindowsLease), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.setProxy("other:1")

	res, err := rig.manager.Recover()
	mustAction(t, res, err, ActionSkippedNotOwner)
	if rig.reg.inet("ProxyServer").Data != "other:1" {
		t.Fatal("a foreign setting must stay")
	}
}

const legacyLinuxLease = `{
  "phase": "Active",
  "ownerToken": "t",
  "endpoints": {"httpPort": 10809, "socksPort": 10808},
  "snapshot": {"gnomeMode": "manual", "gnomeHttpHost": "proxy.corp", "gnomeHttpPort": 3128, "gnomeHttpEnabled": true,
               "gnomeIgnoreHosts": "['localhost']", "kdeProxyType": "0"}
}`

func TestAnOldLinuxLeaseIsRestored(t *testing.T) {
	m, f := newLinuxRig(t)
	if err := os.WriteFile(m.leasePath, []byte(legacyLinuxLease), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := m.Recover()
	mustAction(t, res, err, ActionRecovered)
	if f.gsets["org.gnome.system.proxy.http host"] != "'proxy.corp'" || f.gsets["org.gnome.system.proxy mode"] != "'manual'" {
		t.Fatalf("the user's GNOME proxy must come back: %v", f.gsets)
	}
}

const legacyMacLease = `{
  "phase": "Active",
  "ownerToken": "t",
  "endpoints": {"httpPort": 10809, "socksPort": 10808},
  "services": [{"service": "Wi-Fi",
    "web": {"enabled": false, "host": "", "port": 0},
    "secureWeb": {"enabled": false, "host": "", "port": 0},
    "socks": {"enabled": true, "host": "10.0.0.1", "port": 1080},
    "bypass": ["*.local"]}]
}`

func TestAnOldMacLeaseIsRestored(t *testing.T) {
	m, f := newMacRig(t)
	if err := os.WriteFile(m.leasePath, []byte(legacyMacLease), 0o600); err != nil {
		t.Fatal(err)
	}
	f.services["Wi-Fi"].socks = MacProxyState{Enabled: true, Host: "127.0.0.1", Port: 10808}

	res, err := m.Recover()
	mustAction(t, res, err, ActionRecovered)
	if got := f.services["Wi-Fi"].socks; got != (MacProxyState{Enabled: true, Host: "10.0.0.1", Port: 1080}) {
		t.Fatalf("the user's SOCKS proxy must come back: %+v", got)
	}
}

func TestTheDefaultLeaseFileKeepsTheNameTheOldHostUsed(t *testing.T) {
	dir := t.TempDir()
	got := NewDefault(dir).leasePath
	want := map[string]string{
		"windows": "system-proxy-lease.json",
		"darwin":  "mac-system-proxy-lease.json",
		"linux":   "linux-system-proxy-lease.json",
	}[goos]
	if want == "" {
		t.Skip("no old host on " + goos)
	}
	if filepath.Base(got) != want {
		t.Fatalf("lease file = %s, want %s", filepath.Base(got), want)
	}
}
