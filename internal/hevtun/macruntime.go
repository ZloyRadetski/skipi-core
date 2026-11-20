// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hevtun

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ZloyRadetski/skipi-core/internal/hevpayload"
)

const macHevName = "hev-socks5-tunnel"

// installMacRuntime writes the hev this Core carries into dir and returns its path and the SHA-256
// of the carried bytes. The supervisor copies the file as root and runs the copy only when it has
// that hash, so replacing the written file (dir belongs to the user) gains nothing. No build tag:
// the payload is injected, so it is tested on every host.
func installMacRuntime(files func() ([]hevpayload.File, error), dir string) (path, sha256 string, err error) {
	carried, err := files()
	if err != nil {
		return "", "", fmt.Errorf("HEV TUN is not available: %w", err)
	}
	for _, f := range carried {
		if f.Name != macHevName {
			continue
		}
		path = filepath.Join(dir, macHevName)
		tmp := path + ".new"
		if err := os.WriteFile(tmp, f.Data, 0o755); err != nil {
			return "", "", err
		}
		if err := os.Chmod(tmp, 0o755); err != nil {
			_ = os.Remove(tmp)
			return "", "", err
		}
		if err := os.Rename(tmp, path); err != nil {
			_ = os.Remove(tmp)
			return "", "", err
		}
		return path, f.SHA256(), nil
	}
	return "", "", fmt.Errorf("HEV TUN is not available: the runtime this SKIPI Core carries has no %s", macHevName)
}
