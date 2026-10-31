// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package tunhost

import (
	"strings"
	"testing"

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
