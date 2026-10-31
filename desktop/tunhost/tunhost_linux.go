// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build linux

// Package tunhost is the one TUN session of the desktop Core: the NetworkManager-created
// interface plus the socket binding that keeps Core's own connections off it.
package tunhost

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/ZloyRadetski/skipi-core/desktop/netbind"
	"github.com/ZloyRadetski/skipi-core/desktop/nmtun"
	"github.com/xtls/xray-core/transport/internet"
)

var (
	mu      sync.Mutex
	session *nmtun.Session

	register    sync.Once
	registerErr error
	binder      atomic.Pointer[netbind.Binder]
)

// Prepare binds Core's own outbound sockets to the physical interface. Call it before Core starts so
// no connection of the session is ever made without the binding; Close undoes it.
func Prepare(name string) error {
	if err := nmtun.CheckInterfaceName(name); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	_, err := prepareLocked(name)
	return err
}

// Prepared reports whether the socket binding is in place.
func Prepared() bool { return binder.Load() != nil }

// prepareLocked reports whether this call put the binding in place.
func prepareLocked(name string) (bool, error) {
	if binder.Load() != nil {
		return false, nil
	}
	next := netbind.NewSystemBinder(name)
	next.Enable()
	register.Do(func() {
		registerErr = internet.RegisterDialerController(func(network, address string, c syscall.RawConn) error {
			if current := binder.Load(); current != nil {
				return current.Control(network, address, c)
			}
			return nil
		})
	})
	// Without the binding the tunnel would carry Core's own connections back into itself.
	if registerErr != nil {
		return false, fmt.Errorf("cannot keep Core connections off the tunnel: %w", registerErr)
	}
	binder.Store(next)
	return true, nil
}

// Open brings the interface described by planJSON up and returns the attached tun fd. Core's
// outbound sockets are bound to the physical interface until Close.
func Open(planJSON string) (int, error) {
	plan, err := nmtun.ParsePlan(planJSON)
	if err != nil {
		return -1, err
	}
	if _, err := plan.Settings(0, "validate"); err != nil {
		return -1, err
	}

	mu.Lock()
	defer mu.Unlock()
	if session != nil {
		return -1, errors.New("a TUN session is already open")
	}

	// The binding must be in place before the routes are, or the tunnel's own traffic could loop.
	preparedHere, err := prepareLocked(plan.Name)
	if err != nil {
		return -1, err
	}
	opened, err := nmtun.Open(plan)
	if err != nil {
		if preparedHere {
			releaseLocked()
		}
		return -1, err
	}
	session = opened
	return opened.FD(), nil
}

func releaseLocked() {
	if current := binder.Load(); current != nil {
		current.Disable()
		binder.Store(nil)
	}
}

// Close ends the session and the socket binding; NetworkManager removes the interface and its routes.
func Close() error {
	mu.Lock()
	defer mu.Unlock()
	releaseLocked()
	if session == nil {
		return nil
	}
	err := session.Close()
	session = nil
	return err
}

// Probe returns nil when a TUN session can be opened on this machine, otherwise the reason it cannot.
func Probe() error { return nmtun.Probe() }
