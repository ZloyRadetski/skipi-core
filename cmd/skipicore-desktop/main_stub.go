// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !cgo

package main

// The desktop shared library requires cgo. This stub keeps ordinary Go test
// discovery valid on hosts where cgo is intentionally disabled.
func main() {}
