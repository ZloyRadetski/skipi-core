// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

// Interfaces implemented by the host app (Kotlin/Java through gomobile) and called by the core.

// CoreCallbackHandler handles lifecycle and logging events from the core.
type CoreCallbackHandler interface {
	Startup() int64
	Shutdown() int64
	OnEmitStatus(code int64, message string) int64
}

// ProcessFinder is an interface for Android process-based routing (Split Tunneling).
type ProcessFinder interface {
	FindProcessByConnection(network, srcIP string, srcPort int, destIP string, destPort int) int
}

// SocketProtector matches the gomobile interface for Android VpnService.protect(int).
type SocketProtector interface {
	Protect(fd int) bool
}
