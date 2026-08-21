// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !android

package skipicore

// RegisterProcessFinder is a no-op on non-Android host platforms.
func (c *CoreController) RegisterProcessFinder(finder ProcessFinder) {
}
