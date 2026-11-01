// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build darwin

package tunhost

import "testing"

// On macOS the tunnel process is started by the host with the rights it asked the user for, so Core
// itself needs none: it only keeps its own sockets off the utun interface.
func TestProbeNeedsNoRightsInsideCore(t *testing.T) {
	if err := Probe(); err != nil {
		t.Fatalf("Probe = %v; the privileged part is the host's", err)
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

	if err := Prepare("utun9"); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !Prepared() {
		t.Fatal("the socket binding must be in place after Prepare")
	}
	if err := Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if Prepared() {
		t.Fatal("Close must release the socket binding")
	}
}

func TestOpenIsNotUsedOnMacWhereTheTunnelProcessCreatesUtun(t *testing.T) {
	if fd, err := Open(`{"name":"utun9","mtu":1400,"addresses":["10.0.0.1/24"],"routes":[]}`); err == nil || fd >= 0 {
		t.Fatalf("Open = %d, %v; the utun interface is created by the tunnel process", fd, err)
	}
}
