// Based on net-merge (https://github.com/net-merge/net-merge), Copyright (c) 2026 Rohit Mahto, MIT License;
// see third_party/net-merge. Changes for SKIPI Core: Copyright 2026, Radetski, GPL-3.0.

// Package nics describes the links link merging spreads connections over, and binds sockets to them. The discovery of
// a computer's adapters is left out on Android (build tag android), whose host reports its networks itself.
package nics

import "net"

// Nic is one physical adapter with the source addresses flows are pinned to: its IPv4 address
// and/or its global IPv6 address (either may be nil).
type Nic struct {
	// ID stays the same when the adapter is renamed: the adapter GUID on Windows, the name elsewhere.
	ID    string
	Name  string
	Index int // interface index, used to force egress (IP_UNICAST_IF); 0 = don't force
	// Handle names the link to the host that owns the networks (Android's network handle); 0 = none. A link with
	// a handle is bound through HostBinder instead of by its interface index.
	Handle uint64
	IP     net.IP
	IP6    net.IP
	Weight float64
	Phone  bool // a phone sharing its mobile data: the scheduler goes easy on it (see engine/phone.go)
}

// Skip is an adapter that was seen but not used, with the reason (shown by `net-merge list`).
type Skip struct{ Name, Reason string }
