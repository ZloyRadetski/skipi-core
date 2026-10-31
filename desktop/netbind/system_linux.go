// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build linux

package netbind

import (
	"log"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// NewSystemBinder returns a Binder driven by the kernel's routing table. exclude is the tunnel's
// own interface, which is never chosen.
func NewSystemBinder(exclude string) *Binder {
	return &Binder{
		Lookup: func() (string, bool) {
			table, err := os.ReadFile("/proc/net/route")
			if err != nil {
				return "", false
			}
			return DefaultInterface(string(table), exclude)
		},
		Bind: func(fd uintptr, iface string) error {
			return unix.BindToDevice(int(fd), iface)
		},
		TTL: time.Second,
		Now: time.Now,
		// stderr reaches the application's journal, independent of the Xray log level.
		OnChoose: func(iface string, ok bool) {
			if ok {
				log.Printf("SKIPI TUN: binding Core sockets to %s", iface)
			} else {
				log.Printf("SKIPI TUN: no physical default route; Core sockets follow the system routes")
			}
		},
		OnBindError: func(iface string, err error) {
			log.Printf("SKIPI TUN: SO_BINDTODEVICE %s failed: %v", iface, err)
		},
	}
}
