// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build linux || windows || darwin

package tunhost

import "testing"

func TestPrepareLockedRejectsADifferentInterfaceName(t *testing.T) {
	mu.Lock()
	defer func() { releaseLocked(); mu.Unlock() }()

	if fresh, err := prepareLocked("skipi0"); err != nil || !fresh {
		t.Fatalf("first prepare = %v, %v", fresh, err)
	}
	if fresh, err := prepareLocked("skipi0"); err != nil || fresh {
		t.Fatalf("same name = %v, %v; want not fresh, no error", fresh, err)
	}
	if _, err := prepareLocked("skipi1"); err == nil {
		t.Fatal("a different interface name must not silently keep the old binding")
	}
	releaseLocked()
	if fresh, err := prepareLocked("skipi1"); err != nil || !fresh {
		t.Fatalf("after release = %v, %v", fresh, err)
	}
}
