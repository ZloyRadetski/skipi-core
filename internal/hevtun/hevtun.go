// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package hevtun runs hev-socks5-tunnel (HEV TUN, the C TUN to SOCKS5 forwarder) for Core.
//
//   - Android and Linux (cgo builds): the static libraries are linked into the Core library and
//     hev runs in process on a TUN descriptor the host opened (hevtun_cgo.go).
//   - Windows: hev cannot be loaded in process (its MSYS runtime), so it runs as a supervised
//     child process that creates the Wintun adapter itself (hevtun_windows.go).
//   - Everything else (macOS, builds without cgo): a stub that reports the build lacks it
//     (hevtun_stub.go).
//
// hev is a process singleton, so there is at most one running instance.
package hevtun

import "errors"

var (
	// ErrReadyTimeout is returned by WaitReady when the tunnel is still initializing after the
	// given timeout. It is not fatal: the caller may wait again.
	ErrReadyTimeout = errors.New("HEV TUN is not ready yet")
	// ErrExited is returned by WaitReady when hev main returned before the tunnel was ready.
	ErrExited = errors.New("HEV TUN exited before it became ready")
)
