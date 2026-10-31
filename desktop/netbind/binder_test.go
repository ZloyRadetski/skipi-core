// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package netbind

import (
	"errors"
	"syscall"
	"testing"
	"time"
)

type fakeConn struct{ fd uintptr }

func (f fakeConn) Control(fn func(uintptr)) error { fn(f.fd); return nil }
func (f fakeConn) Read(func(uintptr) bool) error  { return nil }
func (f fakeConn) Write(func(uintptr) bool) error { return nil }

var _ syscall.RawConn = fakeConn{}

func newBinder(iface string, ok bool, bound *[]string) *Binder {
	return &Binder{
		Lookup: func() (string, bool) { return iface, ok },
		Bind: func(fd uintptr, name string) error {
			*bound = append(*bound, name)
			return nil
		},
		TTL: time.Hour,
		Now: func() time.Time { return time.Unix(0, 0) },
	}
}

func TestBinderBindsOutboundSocketsToThePhysicalInterface(t *testing.T) {
	var bound []string
	b := newBinder("enp12s0", true, &bound)
	b.Enable()

	if err := b.Control("tcp", "203.0.113.7:443", fakeConn{3}); err != nil {
		t.Fatal(err)
	}

	if len(bound) != 1 || bound[0] != "enp12s0" {
		t.Fatalf("bound = %v", bound)
	}
}

func TestBinderLeavesLoopbackAndLocalhostAlone(t *testing.T) {
	var bound []string
	b := newBinder("enp12s0", true, &bound)
	b.Enable()

	for _, address := range []string{"127.0.0.1:10808", "[::1]:53", "localhost:80"} {
		if err := b.Control("tcp", address, fakeConn{3}); err != nil {
			t.Fatal(err)
		}
	}

	if len(bound) != 0 {
		t.Fatalf("loopback was bound: %v", bound)
	}
}

func TestBinderDoesNothingWhileDisabledOrWithoutAnInterface(t *testing.T) {
	var bound []string
	b := newBinder("enp12s0", true, &bound)
	_ = b.Control("tcp", "203.0.113.7:443", fakeConn{3})
	b.Enable()
	b.Disable()
	_ = b.Control("tcp", "203.0.113.7:443", fakeConn{3})

	none := newBinder("", false, &bound)
	none.Enable()
	if err := none.Control("tcp", "203.0.113.7:443", fakeConn{3}); err != nil {
		t.Fatal(err)
	}

	if len(bound) != 0 {
		t.Fatalf("bound = %v", bound)
	}
}

func TestBinderCachesTheLookupUntilTheTTLExpires(t *testing.T) {
	var bound []string
	lookups := 0
	now := time.Unix(0, 0)
	b := &Binder{
		Lookup: func() (string, bool) { lookups++; return "enp12s0", true },
		Bind:   func(uintptr, string) error { bound = append(bound, "x"); return nil },
		TTL:    time.Second,
		Now:    func() time.Time { return now },
	}
	b.Enable()

	_ = b.Control("tcp", "203.0.113.7:443", fakeConn{3})
	_ = b.Control("tcp", "203.0.113.8:443", fakeConn{4})
	now = now.Add(2 * time.Second)
	_ = b.Control("tcp", "203.0.113.9:443", fakeConn{5})

	if lookups != 2 {
		t.Fatalf("lookups = %d, want 2", lookups)
	}
}

func TestBinderNeverFailsADialBecauseBindingFailed(t *testing.T) {
	b := &Binder{
		Lookup: func() (string, bool) { return "enp12s0", true },
		Bind:   func(uintptr, string) error { return errors.New("EPERM") },
		TTL:    time.Hour,
		Now:    time.Now,
	}
	b.Enable()

	if err := b.Control("tcp", "203.0.113.7:443", fakeConn{3}); err != nil {
		t.Fatalf("Control = %v", err)
	}
}

func TestBinderReportsAFailedBindOncePerInterfaceAndError(t *testing.T) {
	var reports []string
	b := &Binder{
		Lookup:      func() (string, bool) { return "enp12s0", true },
		Bind:        func(uintptr, string) error { return errors.New("EPERM") },
		OnBindError: func(iface string, err error) { reports = append(reports, iface+": "+err.Error()) },
		TTL:         time.Hour,
		Now:         time.Now,
	}
	b.Enable()

	_ = b.Control("tcp", "203.0.113.7:443", fakeConn{3})
	_ = b.Control("tcp", "203.0.113.8:443", fakeConn{4})

	if len(reports) != 1 || reports[0] != "enp12s0: EPERM" {
		t.Fatalf("reports = %v", reports)
	}
}

func TestBinderReportsTheInterfaceItBindsTo(t *testing.T) {
	var chosen []string
	b := &Binder{
		Lookup:   func() (string, bool) { return "wlp13s0", true },
		Bind:     func(uintptr, string) error { return nil },
		OnChoose: func(iface string, ok bool) { chosen = append(chosen, iface) },
		TTL:      time.Hour,
		Now:      time.Now,
	}
	b.Enable()

	_ = b.Control("tcp", "203.0.113.7:443", fakeConn{3})
	_ = b.Control("tcp", "203.0.113.8:443", fakeConn{4})

	if len(chosen) != 1 || chosen[0] != "wlp13s0" {
		t.Fatalf("chosen = %v", chosen)
	}
}
