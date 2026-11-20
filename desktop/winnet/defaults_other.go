// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !windows

package winnet

import "errors"

var errNotWindows = errors.New("the Wintun network setup exists only on Windows")

// applyPlatformDefaults: off Windows there is nothing to run, and a Net that is used anyway says so.
func applyPlatformDefaults(cfg *Config) {
	if cfg.Run == nil {
		cfg.Run = func([]string) error { return errNotWindows }
	}
	if cfg.AdapterExists == nil {
		cfg.AdapterExists = func(string) bool { return false }
	}
	if cfg.ListAdapters == nil {
		cfg.ListAdapters = func() ([]string, error) { return nil, errNotWindows }
	}
	if cfg.RemoveAdapter == nil {
		cfg.RemoveAdapter = func(string) error { return errNotWindows }
	}
}
