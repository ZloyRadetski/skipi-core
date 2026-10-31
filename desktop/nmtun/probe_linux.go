// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build linux

package nmtun

import (
	"fmt"

	"github.com/godbus/dbus/v5"
)

// Probe reports why a TUN session cannot be opened on this machine, or nil when it can: the system
// bus and NetworkManager must be reachable and grant this user network-control and the right to
// create their own connections.
func Probe() error {
	conn, err := dbus.SystemBusPrivate()
	if err != nil {
		return fmt.Errorf("system bus is unavailable: %w", err)
	}
	defer conn.Close()
	if err := conn.Auth(nil); err != nil {
		return fmt.Errorf("system bus authentication failed: %w", err)
	}
	if err := conn.Hello(); err != nil {
		return fmt.Errorf("system bus handshake failed: %w", err)
	}
	var permissions map[string]string
	call := conn.Object(nmService, nmPath).Call(nmService+".GetPermissions", 0)
	if err := call.Store(&permissions); err != nil {
		return fmt.Errorf("NetworkManager is not running or not reachable: %w", err)
	}
	return checkPermissions(permissions)
}
