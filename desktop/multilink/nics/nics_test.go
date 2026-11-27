// Based on net-merge (https://github.com/net-merge/net-merge), Copyright (c) 2026 Rohit Mahto, MIT License;
// see third_party/net-merge. Changes for SKIPI Core: Copyright 2026, Radetski, GPL-3.0.

package nics

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestLinkCountersReadRealAdapter(t *testing.T) {
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if _, _, ok := Octets(ifc.Index); !ok {
			t.Fatalf("could not read OS counters for %s (index %d)", ifc.Name, ifc.Index)
		}
		return
	}
	t.Skip("no up adapter")
}

// A socket that cannot be bound to its network reports a BindError, whatever the reason.
func TestForceHandleReportsBindErrors(t *testing.T) {
	var c syscall.RawConn = fakeRawConn{}
	SetHostBinder(nil)
	var be *BindError
	if err := ForceHandle(7)("tcp", "192.0.2.1:80", c); !errors.As(err, &be) || !errors.Is(err, ErrNoHostBinder) {
		t.Fatalf("without a binder: %v", err)
	}
	SetHostBinder(func(uint64, uintptr) error { return syscall.EPERM })
	defer SetHostBinder(nil)
	be = nil
	if err := ForceHandle(7)("tcp", "192.0.2.1:80", c); !errors.As(err, &be) || !errors.Is(err, syscall.EPERM) {
		t.Fatalf("with a failing binder: %v", err)
	}
}

type fakeRawConn struct{}

func (fakeRawConn) Control(f func(uintptr)) error     { f(0); return nil }
func (fakeRawConn) Read(func(uintptr) bool) error     { return nil }
func (fakeRawConn) Write(func(uintptr) bool) error    { return nil }
