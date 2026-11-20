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

import (
	"errors"
	"runtime"
	"time"
)

var (
	// ErrReadyTimeout is returned by WaitReady when the tunnel is still initializing after the
	// given timeout. It is not fatal: the caller may wait again.
	ErrReadyTimeout = errors.New("HEV TUN is not ready yet")
	// ErrExited is returned by WaitReady when hev main returned before the tunnel was ready.
	ErrExited = errors.New("HEV TUN exited before it became ready")
)

// Options carries what Start needs besides the YAML; each target reads the fields it uses and
// ignores the rest.
type Options struct {
	// TunFd is the TUN descriptor the host opened (Android, Linux in process); ignored elsewhere.
	TunFd int
	// RunDirectory is where the macOS supervisor keeps its marker files and the generated hev
	// config (created 0700); ignored elsewhere.
	RunDirectory string
	// MacInterface is the macOS utun plan; ignored elsewhere.
	MacInterface *MacInterface
}

// NeedsMacInterface reports whether this target takes the macOS interface plan (Options.MacInterface,
// RunDirectory and Executable) instead of a TUN descriptor.
func NeedsMacInterface() bool { return runtime.GOOS == "darwin" }

// ReadyTimeout is how long a session must be willing to wait for readiness on this target when that
// is longer than its own default: the macOS supervisor may take that long after the administrator
// prompt. Zero elsewhere.
func ReadyTimeout() time.Duration {
	if runtime.GOOS == "darwin" {
		return MacReadyTimeout
	}
	return 0
}
