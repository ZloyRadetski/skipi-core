// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build linux || windows

package tunhost

import (
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/ZloyRadetski/skipi-core/desktop/netbind"
	"github.com/ZloyRadetski/skipi-core/desktop/nmtun"
	"github.com/xtls/xray-core/transport/internet"
)

var (
	mu sync.Mutex

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

func releaseLocked() {
	if current := binder.Load(); current != nil {
		current.Disable()
		binder.Store(nil)
	}
}
