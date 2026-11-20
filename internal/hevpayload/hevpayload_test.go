// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hevpayload

import (
	"errors"
	"testing"
	"testing/fstest"
)

// The hev runtime travels inside the Core library: the release build places the files of the
// target platform into payload/ before compiling, and a build without them reports so clearly.

func TestFilesReturnsEverythingButThePlaceholder(t *testing.T) {
	fsys := fstest.MapFS{
		"payload/.keep":                 {Data: nil},
		"payload/hev-socks5-tunnel.exe": {Data: []byte("exe")},
		"payload/wintun.dll":            {Data: []byte("dll")},
	}
	files, err := filesFrom(fsys, "payload")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range files {
		got[f.Name] = string(f.Data)
	}
	if len(got) != 2 || got["hev-socks5-tunnel.exe"] != "exe" || got["wintun.dll"] != "dll" {
		t.Fatalf("files = %v", got)
	}
}

func TestABuildWithoutThePayloadSaysSo(t *testing.T) {
	_, err := filesFrom(fstest.MapFS{"payload/.keep": {}}, "payload")
	if !errors.Is(err, ErrNotBundled) {
		t.Fatalf("err = %v, want ErrNotBundled", err)
	}
}

func TestSHA256IsTheDigestOfTheContent(t *testing.T) {
	f := File{Name: "a", Data: []byte("abc")}
	if got := f.SHA256(); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("sha256 = %s", got)
	}
}

func TestTheShippedPlaceholderIsTheOnlyFileInAPlainBuild(t *testing.T) {
	// Local builds and the tests carry no hev; a release build is made with the files in place.
	if files, err := Files(); err == nil && len(files) > 0 {
		t.Skip("this build carries a hev payload")
	} else if err != nil && !errors.Is(err, ErrNotBundled) {
		t.Fatal(err)
	}
}
