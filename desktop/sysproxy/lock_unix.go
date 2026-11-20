// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !windows

package sysproxy

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive, non-blocking lock that the system drops with the process, so a
// crashed run never leaves the lock behind.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
