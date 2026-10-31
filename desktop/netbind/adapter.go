// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package netbind

import (
	"math/bits"
	"strings"
)

// Adapter is the part of a network adapter that decides whether it carries the default route.
type Adapter struct {
	Index      uint32
	Name       string
	Up         bool
	HasGateway bool
	Loopback   bool
	// Metric is the adapter's IPv4 interface metric; lower wins.
	Metric uint32
}

// DefaultAdapter returns the index of the up, non-loopback adapter with an IPv4 gateway and the
// lowest metric, ties going to the lower index. The tunnel named by exclude is never chosen
// (compared ignoring case, as Windows adapter names are), so the result stays the physical link
// while the tunnel's own routes are installed.
func DefaultAdapter(adapters []Adapter, exclude string) (uint32, bool) {
	var best *Adapter
	for i := range adapters {
		candidate := &adapters[i]
		if !candidate.Up || !candidate.HasGateway || candidate.Loopback {
			continue
		}
		if exclude != "" && strings.EqualFold(candidate.Name, exclude) {
			continue
		}
		if best == nil || candidate.Metric < best.Metric ||
			(candidate.Metric == best.Metric && candidate.Index < best.Index) {
			best = candidate
		}
	}
	if best == nil {
		return 0, false
	}
	return best.Index, true
}

// UnicastIfValueV4 is the IP_UNICAST_IF option value for an interface index: Winsock wants the
// index of an IPv4 socket in network byte order (IPV6_UNICAST_IF takes it as is).
func UnicastIfValueV4(index uint32) uint32 { return bits.ReverseBytes32(index) }
