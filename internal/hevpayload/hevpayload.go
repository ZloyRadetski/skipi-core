// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package hevpayload carries the hev-socks5-tunnel runtime inside the Core library on the
// platforms where hev runs as a process of its own (Windows and macOS).
//
// The release build copies the files of the target platform into payload/ before compiling
// (scripts/stage-hev-payload.sh); they are embedded here, so the host application ships no hev of
// its own and Core knows the exact bytes (and hash) it runs. A build made without them, such as a
// plain local build, carries only the placeholder and reports ErrNotBundled.
package hevpayload

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"io/fs"
	"path"
)

//go:embed all:payload
var embedded embed.FS

// ErrNotBundled means this Core build carries no hev runtime.
var ErrNotBundled = errors.New("this SKIPI Core build does not carry the HEV TUN runtime")

// File is one file of the runtime, by its name in the install directory.
type File struct {
	Name string
	Data []byte
}

// SHA256 is the lowercase hex digest of the content.
func (f File) SHA256() string {
	sum := sha256.Sum256(f.Data)
	return hex.EncodeToString(sum[:])
}

// Files returns the embedded runtime files, or ErrNotBundled when there are none.
func Files() ([]File, error) { return filesFrom(embedded, "payload") }

func filesFrom(fsys fs.FS, dir string) ([]File, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	var files []File
	for _, e := range entries {
		if e.IsDir() || e.Name() == ".keep" {
			continue
		}
		data, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		files = append(files, File{Name: e.Name(), Data: data})
	}
	if len(files) == 0 {
		return nil, ErrNotBundled
	}
	return files, nil
}
