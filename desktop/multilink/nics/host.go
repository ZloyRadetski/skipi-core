// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package nics

import (
	"errors"
	"sync/atomic"
	"syscall"
)

// HostBinder binds a socket to a network the host owns, by the handle the host gave it. Android's host sets it:
// the system names its networks by handle, not by interface, and a socket is bound to one through the system.
type HostBinder func(handle uint64, fd uintptr) error

var hostBinder atomic.Pointer[HostBinder]

// SetHostBinder installs the binder; nil removes it.
func SetHostBinder(b HostBinder) {
	if b == nil {
		hostBinder.Store(nil)
		return
	}
	hostBinder.Store(&b)
}

// ErrNoHostBinder is returned for a handle when no host binder is installed.
var ErrNoHostBinder = errors.New("no host network binder")

// ForceHandle binds a socket to the host's network with this handle, as ForceEgress does by interface.
func ForceHandle(handle uint64) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		b := hostBinder.Load()
		if b == nil {
			return ErrNoHostBinder
		}
		var serr error
		if err := c.Control(func(fd uintptr) { serr = (*b)(handle, fd) }); err != nil {
			return err
		}
		return serr
	}
}
