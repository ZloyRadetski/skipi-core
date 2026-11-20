// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package winnet

import (
	"strings"
	"testing"
)

// The real Windows seams, which need no administrator: reading the adapters and running a command.
func TestTheNativeAdapterListKnowsTheSystemsAdapters(t *testing.T) {
	cfg := Config{}
	applyPlatformDefaults(&cfg)

	names, err := cfg.ListAdapters()
	if err != nil || len(names) == 0 {
		t.Fatalf("names=%v err=%v", names, err)
	}
	if !cfg.AdapterExists(names[0]) {
		t.Fatalf("%q is listed, so it exists", names[0])
	}
	if cfg.AdapterExists("no-such-adapter-skipi") {
		t.Fatal("an unknown adapter must not exist")
	}
}

func TestACommandRunsWithoutAConsoleAndAFailureCarriesItsOutput(t *testing.T) {
	if err := runHidden([]string{"cmd.exe", "/c", "exit 0"}); err != nil {
		t.Fatal(err)
	}
	err := runHidden([]string{"cmd.exe", "/c", "echo boom & exit 3"})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("got %v", err)
	}
}

func TestWithoutStaleAdaptersNothingIsRemovedAndNoProcessStarts(t *testing.T) {
	removed := false
	n := New(Config{RemoveAdapter: func(string) error { removed = true; return nil }})
	if err := n.RemoveStale("skipitest0"); err != nil || removed {
		t.Fatalf("err=%v removed=%v", err, removed)
	}
}
