// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build darwin

package netbind

import (
	"context"
	"log"
	"net"
	"os/exec"
	"time"

	"golang.org/x/sys/unix"
)

// NewSystemBinder returns a Binder driven by the macOS routing table. exclude is the tunnel's own
// interface, which is never chosen. A socket is pinned with IP_BOUND_IF / IPV6_BOUND_IF, the macOS
// counterpart of SO_BINDTODEVICE.
func NewSystemBinder(exclude string) *Binder {
	return &Binder{
		Lookup: func() (string, bool) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			table, err := exec.CommandContext(ctx, "/usr/sbin/netstat", "-rn", "-f", "inet").Output()
			if err != nil {
				return "", false
			}
			return DefaultInterfaceFromNetstat(string(table), exclude)
		},
		Bind: func(fd uintptr, iface string) error {
			link, err := net.InterfaceByName(iface)
			if err != nil {
				return err
			}
			// A dual-stack socket needs both options; a failure of the family the socket does not
			// have is expected and ignored.
			v4 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, link.Index)
			v6 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, link.Index)
			if v4 != nil && v6 != nil {
				return v4
			}
			return nil
		},
		TTL: time.Second,
		Now: time.Now,
		// stderr reaches the application's log, independent of the Xray log level.
		OnChoose: func(iface string, ok bool) {
			if ok {
				log.Printf("SKIPI TUN: binding Core sockets to %s", iface)
			} else {
				log.Printf("SKIPI TUN: no physical default route; Core sockets follow the system routes")
			}
		},
		OnBindError: func(iface string, err error) {
			log.Printf("SKIPI TUN: IP_BOUND_IF %s failed: %v", iface, err)
		},
	}
}
