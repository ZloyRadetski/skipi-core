// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package netbind

import (
	"errors"
	"sync"
	"sync/atomic"
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
	var mu sync.Mutex
	lookups := 0
	now := time.Unix(0, 0)
	b := &Binder{
		Lookup: func() (string, bool) { mu.Lock(); lookups++; mu.Unlock(); return "enp12s0", true },
		Bind:   func(uintptr, string) error { bound = append(bound, "x"); return nil },
		TTL:    time.Second,
		Now:    func() time.Time { return now },
	}
	b.Enable()

	_ = b.Control("tcp", "203.0.113.7:443", fakeConn{3})
	_ = b.Control("tcp", "203.0.113.8:443", fakeConn{4})
	now = now.Add(2 * time.Second)
	_ = b.Control("tcp", "203.0.113.9:443", fakeConn{5})

	// The expired entry keeps answering while a background lookup replaces it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := lookups
		mu.Unlock()
		if n == 2 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("lookups = %d, want 2", lookups)
}

func TestBinderExpiredLookupDoesNotBlockDials(t *testing.T) {
	release := make(chan struct{})
	var calls int32
	now := time.Unix(0, 0)
	var nowMu sync.Mutex
	b := &Binder{
		Lookup: func() (string, bool) {
			if atomic.AddInt32(&calls, 1) > 1 {
				<-release
			}
			return "enp12s0", true
		},
		Bind: func(uintptr, string) error { return nil },
		TTL:  time.Second,
		Now:  func() time.Time { nowMu.Lock(); defer nowMu.Unlock(); return now },
	}
	b.Enable()
	_ = b.Control("tcp", "203.0.113.7:443", fakeConn{3})
	nowMu.Lock()
	now = now.Add(2 * time.Second)
	nowMu.Unlock()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			_ = b.Control("tcp", "203.0.113.8:443", fakeConn{4})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dials waited for the refresh")
	}
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&calls) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	time.Sleep(50 * time.Millisecond) // a second refresh, if one were wrongly started, would show now
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("lookups = %d, want a single refresh", got)
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
