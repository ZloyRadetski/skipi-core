// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !linux || android

package skipicore

// Android's Xray backend duplicates the descriptor itself and the other platforms do not hand
// Xray a tun descriptor that it closes, so the descriptor is published as is.
func platformDupTunFd(fd int64) (int64, error) { return fd, nil }

func platformCloseTunFd(int64) {}
