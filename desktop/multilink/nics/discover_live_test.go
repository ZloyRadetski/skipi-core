// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !android

package nics

import "testing"

// TestDiscoverLive lists what this machine offers; it checks only what holds everywhere.
func TestDiscoverLive(t *testing.T) {
	found, skipped, err := DiscoverNicsDetailed(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range found {
		if n.ID == "" {
			t.Errorf("adapter %q has no id", n.Name)
		}
		t.Logf("use  %-30s id=%s idx=%d v4=%v v6=%v phone=%v", n.Name, n.ID, n.Index, n.IP, n.IP6, n.Phone)
	}
	for _, s := range skipped {
		t.Logf("skip %-30s %s", s.Name, s.Reason)
	}
}
