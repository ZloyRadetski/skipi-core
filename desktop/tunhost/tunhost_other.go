// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !linux

package tunhost

import "errors"

var errUnsupported = errors.New("TUN mode is not available on this platform yet")

func Open(string) (int, error) { return -1, errUnsupported }

func Close() error { return nil }

func Probe() error { return errUnsupported }

func Prepare(string) error { return errUnsupported }

func Prepared() bool { return false }
