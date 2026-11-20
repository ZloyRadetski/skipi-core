// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !windows

package sysproxy

import "runtime"

func platformBackend() Backend {
	switch runtime.GOOS {
	case "linux":
		return newLinuxBackend(execRunner{})
	case "darwin":
		return newMacBackend(execRunner{})
	}
	return unsupportedBackend{}
}
