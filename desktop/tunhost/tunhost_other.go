// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !linux && !windows && !darwin

package tunhost

import "errors"

var errUnsupported = errors.New("TUN mode is not available on this platform yet")

func Open(string) (int, error) { return -1, errUnsupported }

func Close() error { return nil }

func Probe() error { return errUnsupported }

func Prepare(string) error { return errUnsupported }

func Prepared() bool { return false }

func Attach(string) error { return errUnsupported }

// Protector has nothing to bind to here.
type Protector struct{}

// Protect always succeeds: there is no TUN to keep sockets out of.
func (Protector) Protect(int) bool { return true }
