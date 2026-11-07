// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package netbind

import "encoding/binary"

// Layout of the Windows MIB_IPFORWARD_TABLE2 for 64-bit builds: a 4-byte entry count padded to 8,
// then MIB_IPFORWARD_ROW2 entries of 104 bytes each.
const (
	forwardTableHeader  = 8
	forwardRowSize      = 104
	forwardRowIfIndex   = 8  // InterfaceIndex
	forwardRowFamily    = 12 // DestinationPrefix.Prefix (SOCKADDR_INET) starts with the address family
	forwardRowPrefixLen = 40 // DestinationPrefix.PrefixLength
	forwardRowMetric    = 84 // Metric
	afInet              = 2
)

// defaultRouteMetrics returns, for each interface index, the lowest metric among its IPv4 default
// routes (0.0.0.0/0) in a MIB_IPFORWARD_TABLE2 buffer. Windows ranks routes by this metric plus the
// interface's own, so the interface metric alone does not tell which adapter carries the traffic.
func defaultRouteMetrics(table []byte) map[uint32]uint32 {
	metrics := make(map[uint32]uint32)
	if len(table) < forwardTableHeader {
		return metrics
	}
	count := int(binary.LittleEndian.Uint32(table))
	for i := 0; i < count; i++ {
		start := forwardTableHeader + i*forwardRowSize
		if start+forwardRowSize > len(table) {
			break
		}
		row := table[start : start+forwardRowSize]
		if binary.LittleEndian.Uint16(row[forwardRowFamily:]) != afInet || row[forwardRowPrefixLen] != 0 {
			continue
		}
		index := binary.LittleEndian.Uint32(row[forwardRowIfIndex:])
		metric := binary.LittleEndian.Uint32(row[forwardRowMetric:])
		if current, ok := metrics[index]; !ok || metric < current {
			metrics[index] = metric
		}
	}
	return metrics
}
