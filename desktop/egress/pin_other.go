// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build !linux

package egress

// bindsLinkItself is false off Linux: Windows and macOS let the link be set on a socket the TUN's controller has
// already bound, so the link is passed to Xray's dialer as a socket option.
func bindsLinkItself() bool { return false }
