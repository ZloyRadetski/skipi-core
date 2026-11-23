// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build linux && !android

package skipicore

import "golang.org/x/sys/unix"

// Xray's Linux TUN wraps the descriptor from xray.tun.fd in an os.File and closes it on stop,
// while the desktop TUN session keeps closing its own. Each gets an independent descriptor.
func platformDupTunFd(fd int64) (int64, error) {
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return 0, err
	}
	return int64(dup), nil
}

// platformCloseTunFd closes a duplicate Xray did not take. Xray may have taken it after all, so
// it is only closed while it still names a TUN device.
func platformCloseTunFd(fd int64) {
	if ifr, err := unix.NewIfreq(""); err == nil && unix.IoctlIfreq(int(fd), unix.TUNGETIFF, ifr) == nil {
		_ = unix.Close(int(fd))
	}
}
