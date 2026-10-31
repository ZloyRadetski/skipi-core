// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package notify shows desktop notifications through the freedesktop Desktop Notifications service
// on the session bus, which GNOME, KDE, Xfce and standalone daemons such as mako, dunst or swaync
// all provide. Without such a service the call fails and the caller simply goes on.
package notify

import (
	"fmt"

	"github.com/godbus/dbus/v5"
)

const (
	service      = "org.freedesktop.Notifications"
	path         = dbus.ObjectPath("/org/freedesktop/Notifications")
	appName      = "SKIPI"
	icon         = "network-vpn"
	stackTag     = "skipi-vpn"
	expireMillis = int32(4000)
)

// Show displays a notification. Each call is a new notification; servers that understand the
// stacking hints replace the previous SKIPI one, the others show both.
func Show(summary, body string) error {
	conn, err := dbus.SessionBusPrivate()
	if err != nil {
		return fmt.Errorf("session bus is unavailable: %w", err)
	}
	defer conn.Close()
	if err := conn.Auth(nil); err != nil {
		return fmt.Errorf("session bus authentication failed: %w", err)
	}
	if err := conn.Hello(); err != nil {
		return fmt.Errorf("session bus handshake failed: %w", err)
	}
	var id uint32
	call := conn.Object(service, path).Call(service+".Notify", 0, notifyArgs(summary, body)...)
	if err := call.Store(&id); err != nil {
		return fmt.Errorf("no desktop notification service: %w", err)
	}
	return nil
}

// replaces_id stays 0: replacing by id shows nothing on servers that drop updates for a
// notification that has already expired.
func notifyArgs(summary, body string) []any {
	return []any{
		appName,
		uint32(0),
		icon,
		summary,
		body,
		[]string{},
		map[string]dbus.Variant{
			"x-canonical-private-synchronous": dbus.MakeVariant(stackTag),
			"x-dunst-stack-tag":               dbus.MakeVariant(stackTag),
		},
		expireMillis,
	}
}
