// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package tunhost

import (
	"strings"
	"sync"
	"testing"

	"github.com/ZloyRadetski/skipi-core/desktop/winnet"
	"golang.org/x/sys/windows"
)

func TestProbeRequiresAdministratorRights(t *testing.T) {
	err := Probe()
	if windows.GetCurrentProcessToken().IsElevated() {
		if err != nil {
			t.Fatalf("an elevated process can run TUN, got %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "administrator") {
		t.Fatalf("Probe = %v, want an administrator-rights reason", err)
	}
}

func TestPrepareRejectsAnInvalidInterfaceNameBeforeTouchingTheSystem(t *testing.T) {
	if err := Prepare("a/b"); err == nil {
		t.Fatal("expected a validation error")
	}
	if Prepared() {
		t.Fatal("nothing must be bound after a rejected name")
	}
}

func TestPrepareBindsCoreSocketsAndCloseUndoesIt(t *testing.T) {
	t.Cleanup(func() { _ = Close() })

	if err := Prepare("skipi0"); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !Prepared() {
		t.Fatal("the socket binding must be in place after Prepare")
	}
	if err := Prepare("skipi0"); err != nil {
		t.Fatalf("a second Prepare must be harmless: %v", err)
	}

	if err := Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if Prepared() {
		t.Fatal("Close must release the socket binding")
	}
}

func TestOpenIsNotUsedOnWindowsWhereTheHostCreatesTheAdapter(t *testing.T) {
	if fd, err := Open(`{"name":"skipi0","mtu":1400,"addresses":["10.0.0.1/24"],"routes":[]}`); err == nil || fd >= 0 {
		t.Fatalf("Open = %d, %v; the Windows adapter is created by the tunnel process", fd, err)
	}
}

// ---- the network setup around the adapter hev creates ----------------------------------------------

type fakeWindowsNet struct {
	mu      sync.Mutex
	ran     []string
	removed []string
	stale   []string
}

func (f *fakeWindowsNet) use(t *testing.T) {
	t.Helper()
	previous := windowsNet
	windowsNet = winnet.New(winnet.Config{
		Run: func(command []string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.ran = append(f.ran, strings.Join(command, " "))
			return nil
		},
		AdapterExists: func(string) bool { return true },
		ListAdapters:  func() ([]string, error) { return append([]string{"Ethernet"}, f.stale...), nil },
		RemoveAdapter: func(name string) error { f.mu.Lock(); f.removed = append(f.removed, name); f.mu.Unlock(); return nil },
		Serial:        true,
		Background:    func(task func()) { task() },
	})
	t.Cleanup(func() { windowsNet = previous })
}

func (f *fakeWindowsNet) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ran...)
}

const windowsTestPlan = `{"name":"skipi0","mtu":1400,"addresses":["172.19.0.1/30"],"routes":["0.0.0.0/1","128.0.0.0/1"],"dns":[]}`

func TestPrepareRemovesAnAdapterAnEarlierSessionLeftBehind(t *testing.T) {
	fake := &fakeWindowsNet{stale: []string{"skipi0 1"}}
	fake.use(t)
	t.Cleanup(func() { _ = Close() })

	if err := Prepare("skipi0"); err != nil {
		t.Fatal(err)
	}
	if len(fake.removed) == 0 || fake.removed[0] != "skipi0" {
		t.Fatalf("the stale adapter must be gone before hev creates its own: %v", fake.removed)
	}
}

func TestPrepareWithNothingLeftBehindRemovesNothing(t *testing.T) {
	fake := &fakeWindowsNet{}
	fake.use(t)
	t.Cleanup(func() { _ = Close() })

	if err := Prepare("skipi0"); err != nil {
		t.Fatal(err)
	}
	if len(fake.removed) != 0 {
		t.Fatalf("removed %v", fake.removed)
	}
}

func TestAttachInstallsTheRoutesAndCloseRemovesThem(t *testing.T) {
	fake := &fakeWindowsNet{}
	fake.use(t)
	t.Cleanup(func() { _ = Close() })

	if err := Attach(windowsTestPlan); err != nil {
		t.Fatal(err)
	}
	ran := strings.Join(fake.commands(), "\n")
	if !strings.Contains(ran, "add route prefix=0.0.0.0/1 interface=skipi0") || !strings.Contains(ran, "add route prefix=128.0.0.0/1 interface=skipi0") {
		t.Fatalf("routes not installed:\n%s", ran)
	}

	if err := Close(); err != nil {
		t.Fatal(err)
	}
	ran = strings.Join(fake.commands(), "\n")
	if !strings.Contains(ran, "delete route prefix=0.0.0.0/1 interface=skipi0") {
		t.Fatalf("routes not removed:\n%s", ran)
	}
}

func TestAttachRefusesAPlanItCannotReadWithoutRunningAnything(t *testing.T) {
	fake := &fakeWindowsNet{}
	fake.use(t)

	if err := Attach(`not json`); err == nil {
		t.Fatal("a broken plan must fail")
	}
	if len(fake.commands()) != 0 {
		t.Fatalf("nothing may run: %v", fake.commands())
	}
}
