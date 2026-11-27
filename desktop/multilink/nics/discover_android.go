// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build android

package nics

import "errors"

// Android's host owns the networks and reports them (see internal/hostlinks), so the scanning of a computer's adapters
// is not built in: it would carry a netlink client and the name filters for nothing.

// ErrNoDiscovery is what discovery returns where the host reports the links.
var ErrNoDiscovery = errors.New("the host reports its links, there is nothing to scan")

func DiscoverNicsDetailed([]string, map[string]float64) ([]Nic, []Skip, error) {
	return nil, nil, ErrNoDiscovery
}

// AdapterKinds has nothing to read here: the host names each link's kind.
func AdapterKinds() map[string]Kind { return nil }
