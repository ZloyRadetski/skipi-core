// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !android && !ios

package skipicore

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	corefilesystem "github.com/xtls/xray-core/common/platform/filesystem"
)

func TestInitCoreEnvUsesFilesystemReaderOnHost(t *testing.T) {
	directory := t.TempDir()
	assetPath := filepath.Join(directory, "geoip.dat")
	if err := os.WriteFile(assetPath, []byte("host asset"), 0o600); err != nil {
		t.Fatalf("write test asset: %v", err)
	}

	InitCoreEnv(directory, "")
	reader, err := corefilesystem.NewFileReader(assetPath)
	if err != nil {
		t.Fatalf("open host asset: %v", err)
	}
	defer reader.Close()

	contents, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read host asset: %v", err)
	}
	if got := string(contents); got != "host asset" {
		t.Fatalf("unexpected host asset contents: %q", got)
	}
}
