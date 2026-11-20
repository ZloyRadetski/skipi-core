// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package sysproxy

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile takes an exclusive, non-blocking lock that the system drops with the process, so a
// crashed run never leaves the lock behind.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, overlapped)
		_ = f.Close()
	}, nil
}
