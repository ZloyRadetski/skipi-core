// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package hevtun runs hev-socks5-tunnel (HEV TUN, the C TUN to SOCKS5 forwarder) inside the
// Core process. Android links its static libraries into libgojni.so through cgo
// (hevtun_android.go); every other platform gets a stub (hevtun_other.go) that reports the
// build lacks it. hev is a process singleton, so there is at most one running instance.
package hevtun

import "errors"

var (
	// ErrReadyTimeout is returned by WaitReady when the tunnel is still initializing after the
	// given timeout. It is not fatal: the caller may wait again.
	ErrReadyTimeout = errors.New("HEV TUN is not ready yet")
	// ErrExited is returned by WaitReady when hev main returned before the tunnel was ready.
	ErrExited = errors.New("HEV TUN exited before it became ready")
)
