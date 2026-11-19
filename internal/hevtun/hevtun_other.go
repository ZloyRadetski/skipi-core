// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !android

package hevtun

import (
	"fmt"
	"runtime"
	"time"
)

func notBuilt() error {
	return fmt.Errorf("HEV TUN is not built into this Core on %s", runtime.GOOS)
}

// Start always fails: this Core was built without HEV TUN.
func Start(configYAML string, tunFd int) error { return notBuilt() }

// WaitReady always fails: this Core was built without HEV TUN.
func WaitReady(timeout time.Duration) error { return notBuilt() }

// Stop has nothing to stop.
func Stop() error { return nil }

// Stats reports zeros.
func Stats() (txPackets, txBytes, rxPackets, rxBytes uint64) { return 0, 0, 0, 0 }

// Running is always false.
func Running() bool { return false }
