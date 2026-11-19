// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build darwin

// Package tunhost is the TUN session of the desktop Core. On macOS Core's HEV TUN supervisor
// (internal/hevtun) runs hev-socks5-tunnel with administrator rights obtained through osascript;
// hev creates the utun interface itself and the supervisor installs the routes. This package's part
// is the socket binding that keeps Core's own connections off that interface.
package tunhost

import "errors"

var errHostCreatesInterface = errors.New("on macOS the tunnel process creates the utun interface; there is no descriptor to open")

// Open is not used on macOS: there is no tun descriptor to hand over.
func Open(string) (int, error) { return -1, errHostCreatesInterface }

// Close ends the socket binding.
func Close() error {
	mu.Lock()
	defer mu.Unlock()
	releaseLocked()
	return nil
}

// Probe returns nil: the administrator rights are obtained by Core's HEV TUN supervisor when it starts the tunnel,
// and the socket binding itself needs none.
func Probe() error { return nil }
