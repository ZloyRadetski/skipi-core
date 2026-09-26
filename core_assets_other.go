// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !android && !ios

package skipicore

import (
	"io"
	"os"

	corefilesystem "github.com/xtls/xray-core/common/platform/filesystem"
)

// configureCoreAssetReader deliberately has no mobile-asset fallback on desktop hosts.
// SKIPI Desktop installs geo resources into a private filesystem directory before core
// startup, so surfacing an ordinary file error is safer than trying an Android APK API.
func configureCoreAssetReader() {
	corefilesystem.NewFileReader = func(path string) (io.ReadCloser, error) {
		return os.Open(path)
	}
}
