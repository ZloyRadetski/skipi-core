// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hevtun

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ZloyRadetski/skipi-core/internal/hevpayload"
)

func carried(files ...hevpayload.File) func() ([]hevpayload.File, error) {
	return func() ([]hevpayload.File, error) { return files, nil }
}

// macOS runs hev as root from a copy the supervisor makes, and checks that copy against the hash
// Core gives it. Core writes out the hev it carries and hands over the hash of those bytes.
func TestMacRuntimeWritesTheCarriedHevAndReportsItsHash(t *testing.T) {
	dir := t.TempDir()
	hev := hevpayload.File{Name: "hev-socks5-tunnel", Data: []byte("\xcf\xfa\xed\xfe macho")}
	path, sum, err := installMacRuntime(carried(hev, hevpayload.File{Name: "HEV_LICENSE.txt", Data: []byte("MIT")}), dir)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "hev-socks5-tunnel") || sum != hev.SHA256() {
		t.Fatalf("path = %s, sum = %s", path, sum)
	}
	if got, _ := os.ReadFile(path); string(got) != string(hev.Data) {
		t.Fatalf("content = %q", got)
	}
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("mode = %v, want executable", info.Mode())
	}
}

// The hash is the one of the embedded bytes, never of the file on disk: a user who replaces the
// written file cannot make root accept it.
func TestMacRuntimeHashIsOfTheCarriedBytesWhateverIsOnDisk(t *testing.T) {
	dir := t.TempDir()
	hev := hevpayload.File{Name: "hev-socks5-tunnel", Data: []byte("real")}
	if err := os.WriteFile(filepath.Join(dir, "hev-socks5-tunnel"), []byte("planted"), 0o755); err != nil {
		t.Fatal(err)
	}
	path, sum, err := installMacRuntime(carried(hev), dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "real" || sum != hev.SHA256() {
		t.Fatalf("content = %q, sum = %s", got, sum)
	}
}

func TestMacRuntimeWithoutThePayloadOrTheExecutableFailsClearly(t *testing.T) {
	missing := func() ([]hevpayload.File, error) { return nil, hevpayload.ErrNotBundled }
	if _, _, err := installMacRuntime(missing, t.TempDir()); !errors.Is(err, hevpayload.ErrNotBundled) || !strings.Contains(err.Error(), "does not carry") {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := installMacRuntime(carried(hevpayload.File{Name: "other", Data: []byte("x")}), t.TempDir()); err == nil {
		t.Fatal("a payload without the hev executable must fail")
	}
}
