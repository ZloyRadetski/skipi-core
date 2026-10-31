// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package netbind keeps SKIPI's own outbound sockets off the tunnel it serves:
// it finds the physical interface that carries the system default route so
// dialers can bind to it.
package netbind

import (
	"strconv"
	"strings"
)

const (
	routeUp      = 0x1
	routeGateway = 0x2
)

// DefaultInterface returns the interface of the lowest-metric IPv4 default route in a
// /proc/net/route table. The tunnel interface named by exclude is never chosen, so the result
// stays the physical link while the tunnel's own routes are installed.
func DefaultInterface(table string, exclude string) (string, bool) {
	best := ""
	bestMetric := int64(-1)
	for _, line := range strings.Split(table, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[0] == "Iface" {
			continue
		}
		name := fields[0]
		if name == exclude || fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&routeUp == 0 || flags&routeGateway == 0 {
			continue
		}
		metric, err := strconv.ParseInt(fields[6], 10, 64)
		if err != nil {
			continue
		}
		if bestMetric < 0 || metric < bestMetric {
			best, bestMetric = name, metric
		}
	}
	return best, best != ""
}
