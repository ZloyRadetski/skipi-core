// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build android && cgo

package hostlinks

/*
#cgo LDFLAGS: -landroid
#include <android/multinetwork.h>
#include <errno.h>
#include <stdint.h>

static int skipi_bind_to_network(uint64_t handle, int fd) {
	return android_setsocknetwork((net_handle_t)handle, fd) == 0 ? 0 : errno;
}
*/
import "C"

import (
	"syscall"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink/nics"
)

// InstallBinder makes sockets of links with a handle bind to their network through android_setsocknetwork.
func InstallBinder() {
	nics.SetHostBinder(func(handle uint64, fd uintptr) error {
		if errno := C.skipi_bind_to_network(C.uint64_t(handle), C.int(fd)); errno != 0 {
			return &nics.BindError{Err: syscall.Errno(errno)}
		}
		return nil
	})
}
