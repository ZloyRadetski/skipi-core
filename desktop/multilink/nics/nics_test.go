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

func TestIsPhoneFindsAnIPhoneHotspot(t *testing.T) {
	for _, c := range []struct {
		ip   string
		bits int
		desc string
		want bool
	}{
		{"172.20.10.2", 28, "", true},                 // Personal Hotspot over Wi-Fi: only the address tells
		{"172.20.10.14", 28, "Wi-Fi", true},           // the last address of the /28
		{"", 0, "iPhone USB", true},                   // macOS, before DHCP
		{"", 0, "Apple Mobile Device Ethernet", true}, // Windows
		{"", 0, "ipheth", true},                       // Linux driver
		{"172.20.10.5", 16, "Wi-Fi", false},           // an office or campus network on 172.20.0.0/16
		{"172.20.10.5", 24, "Ethernet", false},        // a /24 that happens to sit there
		{"172.20.10.16", 28, "Wi-Fi", false},          // next door to the /28
		{"192.168.1.20", 24, "Wi-Fi", false},
		{"172.20.11.2", 28, "Ethernet", false},
		{"10.0.0.5", 8, "r8169", false},
		{"", 0, "", false},
	} {
		if got := isPhone(net.ParseIP(c.ip).To4(), c.bits, c.desc); got != c.want {
			t.Errorf("isPhone(%q, /%d, %q) = %v, want %v", c.ip, c.bits, c.desc, got, c.want)
		}
	}
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
