// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package netbind

import (
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Binder is a dialer controller that pins SKIPI's own outbound sockets to the physical interface,
// so the proxy connections to the servers never enter the tunnel they carry. Loopback is left
// alone because the tunnel reaches Core over it.
type Binder struct {
	// Lookup returns the interface that should carry outbound traffic.
	Lookup func() (string, bool)
	// Bind pins one socket to an interface.
	Bind func(fd uintptr, iface string) error
	// TTL bounds how long a lookup result is reused.
	TTL time.Duration
	Now func() time.Time
	// OnChoose, when set, hears each change of the chosen interface.
	OnChoose func(iface string, ok bool)
	// OnBindError, when set, hears a failed bind once per interface and error text.
	OnBindError func(iface string, err error)

	mu        sync.Mutex
	enabled   bool
	iface     string
	ok        bool
	refreshed time.Time
	announced bool
	// refreshing is set while one background lookup runs; everyone else keeps the previous answer.
	refreshing bool
	reported   map[string]bool
}

func (b *Binder) Enable() {
	b.mu.Lock()
	b.enabled, b.refreshed = true, time.Time{}
	b.mu.Unlock()
}

func (b *Binder) Disable() {
	b.mu.Lock()
	b.enabled = false
	b.mu.Unlock()
}

// current returns the interface to bind to. The first answer after Enable is looked up in line,
// so no socket of the session goes unbound. Later expiries refresh in the background while the
// previous answer keeps serving: the lookup asks the OS for every adapter and route, and a dial
// must not wait for it once a second.
func (b *Binder) current() (string, bool) {
	b.mu.Lock()
	if !b.enabled {
		b.mu.Unlock()
		return "", false
	}
	now := b.Now()
	switch {
	case b.refreshed.IsZero():
		// Concurrent first dials queue behind this one instead of each asking the OS.
		iface, ok := b.Lookup()
		changed := b.store(iface, ok, now)
		onChoose := b.OnChoose
		b.mu.Unlock()
		if changed && onChoose != nil {
			onChoose(iface, ok)
		}
		return iface, ok
	case now.Sub(b.refreshed) >= b.TTL && !b.refreshing:
		b.refreshing = true
		go b.refresh()
	}
	iface, ok := b.iface, b.ok
	b.mu.Unlock()
	return iface, ok
}

func (b *Binder) refresh() {
	iface, ok := b.Lookup()
	b.mu.Lock()
	b.refreshing = false
	if !b.enabled {
		b.mu.Unlock()
		return
	}
	changed := b.store(iface, ok, b.Now())
	onChoose := b.OnChoose
	b.mu.Unlock()
	if changed && onChoose != nil {
		onChoose(iface, ok)
	}
}

// store records an answer and reports whether it differs from the announced one. b.mu is held.
func (b *Binder) store(iface string, ok bool, now time.Time) bool {
	changed := !b.announced || iface != b.iface || ok != b.ok
	b.iface, b.ok, b.refreshed, b.announced = iface, ok, now, true
	return changed
}

func (b *Binder) reportBindError(iface string, err error) {
	if b.OnBindError == nil {
		return
	}
	key := iface + "\x00" + err.Error()
	b.mu.Lock()
	if b.reported == nil {
		b.reported = make(map[string]bool)
	}
	first := !b.reported[key]
	b.reported[key] = true
	b.mu.Unlock()
	if first {
		b.OnBindError(iface, err)
	}
}

// Control matches the signature Xray's dialer controllers use. A failed bind never fails the dial:
// the connection then simply follows the system routes.
func (b *Binder) Control(network, address string, c syscall.RawConn) error {
	if isLoopback(address) {
		return nil
	}
	iface, ok := b.current()
	if !ok {
		return nil
	}
	return c.Control(func(fd uintptr) {
		if err := b.Bind(fd, iface); err != nil {
			b.reportBindError(iface, err)
		}
	})
}

func isLoopback(address string) bool {
	if strings.HasPrefix(strings.ToLower(address), "localhost:") {
		return true
	}
	if addrPort, err := netip.ParseAddrPort(address); err == nil {
		return addrPort.Addr().IsLoopback()
	}
	return false
}
