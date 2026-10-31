// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

// Package tunhost is the TUN session of the desktop Core. On Windows the host application runs
// hev-socks5-tunnel, which creates the Wintun adapter itself, so Core's part is the socket binding
// that keeps its own connections off that adapter, and the check that the process may use TUN.
package tunhost

import (
	"errors"

	"golang.org/x/sys/windows"
)

var errHostCreatesAdapter = errors.New("on Windows the tunnel process creates the TUN adapter; there is no descriptor to open")

// Open is not used on Windows: there is no tun descriptor to hand over.
func Open(string) (int, error) { return -1, errHostCreatesAdapter }

// Close ends the socket binding.
func Close() error {
	mu.Lock()
	defer mu.Unlock()
	releaseLocked()
	return nil
}

// Probe returns nil when this process may create a TUN adapter and routes, otherwise the reason.
func Probe() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("TUN mode needs administrator rights; restart SKIPI as administrator")
	}
	return nil
}
