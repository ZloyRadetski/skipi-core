// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

// Package tunhost is the TUN session of the desktop Core. On Windows the host application runs
// hev-socks5-tunnel, which creates the Wintun adapter itself, so Core's part is the socket binding
// that keeps its own connections off that adapter, and the check that the process may use TUN.
package tunhost

import (
	"errors"
	"log"

	"github.com/ZloyRadetski/skipi-core/desktop/winnet"
	"golang.org/x/sys/windows"
)

// windowsNet sets up the network around the adapter hev creates: routes, DNS, the multicast block and the
// removal of adapters an earlier session left behind.
var windowsNet = winnet.New(winnet.Config{})

// platformPrepare removes the adapters an earlier session left behind before hev creates its own: a hev
// process that is terminated cannot close its adapter, and Wintun then names the next one "skipi0 1". It is
// only a quick listing when nothing is left. A failure is not fatal: a stale adapter only stays in the list.
func platformPrepare(name string) {
	if err := windowsNet.RemoveStale(name); err != nil {
		log.Printf("SKIPI TUN: could not remove stale adapters: %v", err)
	}
}

// Attach installs the routes into the adapter once hev has created it, and the DNS servers and the multicast
// block behind them. planJSON is the host's device plan.
func Attach(planJSON string) error {
	plan, err := winnet.ParsePlan(planJSON)
	if err != nil {
		return err
	}
	return windowsNet.Attach(plan)
}

var errHostCreatesAdapter = errors.New("on Windows the tunnel process creates the TUN adapter; there is no descriptor to open")

// Open is not used on Windows: there is no tun descriptor to hand over.
func Open(string) (int, error) { return -1, errHostCreatesAdapter }

// Close ends the socket binding.
func Close() error {
	mu.Lock()
	defer mu.Unlock()
	releaseLocked()
	// The routes go first, which is all the disconnect waits for; the dead adapter is removed behind it.
	err := windowsNet.Detach()
	if name := preparedName; name != "" {
		preparedName = ""
		windowsNet.RemoveStaleLater(name)
	}
	return err
}

// Probe returns nil when this process may create a TUN adapter and routes, otherwise the reason.
func Probe() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("TUN mode needs administrator rights; restart SKIPI as administrator")
	}
	return nil
}
