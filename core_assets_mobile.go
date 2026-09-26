// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build android || ios

package skipicore

import (
	"io"
	"os"
	"path/filepath"

	corefilesystem "github.com/xtls/xray-core/common/platform/filesystem"
	mobasset "golang.org/x/mobile/asset"
)

// configureCoreAssetReader keeps the mobile bundled-asset fallback. Geo files normally
// live in the app data directory, but gomobile can read a bundled asset by filename
// before the host has materialized it there.
func configureCoreAssetReader() {
	corefilesystem.NewFileReader = func(path string) (io.ReadCloser, error) {
		if file, err := os.Open(path); err == nil {
			return file, nil
		}
		_, file := filepath.Split(path)
		return mobasset.Open(file)
	}
}
