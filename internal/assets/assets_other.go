// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !android && !ios

package assets

import (
	"io"
	"os"

	corefilesystem "github.com/xtls/xray-core/common/platform/filesystem"
)

// Configure deliberately has no mobile-asset fallback on desktop hosts.
// SKIPI Desktop installs geo resources into a private filesystem directory before core
// startup, so surfacing an ordinary file error is safer than trying an Android APK API.
func Configure() {
	corefilesystem.NewFileReader = func(path string) (io.ReadCloser, error) {
		return os.Open(path)
	}
}
