// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package sysproxy

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// The real HKCU, on a scratch key that is removed afterwards.
func TestHkcuRegistryRoundTripsStringsAndDwordsAndDeletesIdempotently(t *testing.T) {
	key := fmt.Sprintf(`Software\SKIPI\Test-%d`, os.Getpid())
	t.Cleanup(func() { _ = registry.DeleteKey(registry.CURRENT_USER, key) })
	reg := hkcuRegistry{}

	if v, err := reg.Read(key, "Missing"); err != nil || v != nil {
		t.Fatalf("a missing value is nil, nil: %v %v", v, err)
	}
	if err := reg.Write(key, "Server", RegValue{Type: regString, Data: "127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Write(key, "Enable", RegValue{Type: regDword, Data: "1"}); err != nil {
		t.Fatal(err)
	}
	if v, _ := reg.Read(key, "Server"); v == nil || *v != (RegValue{Type: regString, Data: "127.0.0.1:1"}) {
		t.Fatalf("string = %+v", v)
	}
	if v, _ := reg.Read(key, "Enable"); v == nil || *v != (RegValue{Type: regDword, Data: "1"}) {
		t.Fatalf("dword = %+v", v)
	}
	for i := 0; i < 2; i++ {
		if err := reg.Delete(key, "Server"); err != nil {
			t.Fatalf("delete #%d: %v", i, err)
		}
	}
	if v, _ := reg.Read(key, "Server"); v != nil {
		t.Fatal("deleted value must be gone")
	}
	if err := reg.Delete(`Software\SKIPI\NoSuchKey-`+key, "x"); err != nil {
		t.Fatalf("deleting under a missing key is not an error: %v", err)
	}
}

func TestWinInetRefreshIsAcceptedBySystem(t *testing.T) {
	if err := refreshWinInet(); err != nil {
		t.Fatal(err)
	}
}
