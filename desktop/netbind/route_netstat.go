// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package netbind

import (
	"net/netip"
	"strings"
)

// DefaultInterfaceFromNetstat returns the interface of the first usable IPv4 default route in the
// text of `netstat -rn -f inet` on macOS, which lists the primary service first. A route is usable
// when it is up (U) and has a gateway address (G, and the gateway is an IP, not `link#N`).
// Interfaces whose name starts with utun are tunnels and the one named by exclude is SKIPI's own,
// so neither is chosen while the tunnel's routes are installed.
func DefaultInterfaceFromNetstat(table string, exclude string) (string, bool) {
	for _, line := range strings.Split(table, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "default" {
			continue
		}
		gateway, flags, netif := fields[1], fields[2], fields[3]
		if netif == exclude || strings.HasPrefix(netif, "utun") || strings.HasPrefix(netif, "lo") {
			continue
		}
		if !strings.Contains(flags, "U") || !strings.Contains(flags, "G") {
			continue
		}
		if _, err := netip.ParseAddr(strings.SplitN(gateway, "%", 2)[0]); err != nil {
			continue
		}
		return netif, true
	}
	return "", false
}
