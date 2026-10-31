// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build linux

// Package tunhost is the one TUN session of the desktop Core: the NetworkManager-created
// interface plus the socket binding that keeps Core's own connections off it.
package tunhost

import (
	"errors"

	"github.com/ZloyRadetski/skipi-core/desktop/nmtun"
)

var session *nmtun.Session

// Open brings the interface described by planJSON up and returns the attached tun fd. Core's
// outbound sockets are bound to the physical interface until Close.
func Open(planJSON string) (int, error) {
	plan, err := nmtun.ParsePlan(planJSON)
	if err != nil {
		return -1, err
	}
	if _, err := plan.Settings(0, "validate"); err != nil {
		return -1, err
	}

	mu.Lock()
	defer mu.Unlock()
	if session != nil {
		return -1, errors.New("a TUN session is already open")
	}

	// The binding must be in place before the routes are, or the tunnel's own traffic could loop.
	preparedHere, err := prepareLocked(plan.Name)
	if err != nil {
		return -1, err
	}
	opened, err := nmtun.Open(plan)
	if err != nil {
		if preparedHere {
			releaseLocked()
		}
		return -1, err
	}
	session = opened
	return opened.FD(), nil
}

// Close ends the session and the socket binding; NetworkManager removes the interface and its routes.
func Close() error {
	mu.Lock()
	defer mu.Unlock()
	releaseLocked()
	if session == nil {
		return nil
	}
	err := session.Close()
	session = nil
	return err
}

// Probe returns nil when a TUN session can be opened on this machine, otherwise the reason it cannot.
func Probe() error { return nmtun.Probe() }
