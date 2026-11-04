// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package netbind

import (
	"encoding/binary"
	"testing"
)

func forwardTable(rows ...[3]uint32) []byte { // {interface index, prefix length, metric}
	table := make([]byte, forwardTableHeader+len(rows)*forwardRowSize)
	binary.LittleEndian.PutUint32(table, uint32(len(rows)))
	for i, r := range rows {
		row := table[forwardTableHeader+i*forwardRowSize:]
		binary.LittleEndian.PutUint32(row[forwardRowIfIndex:], r[0])
		binary.LittleEndian.PutUint16(row[forwardRowFamily:], afInet)
		row[forwardRowPrefixLen] = byte(r[1])
		binary.LittleEndian.PutUint32(row[forwardRowMetric:], r[2])
	}
	return table
}

func TestDefaultRouteMetricsKeepsOnlyDefaultRoutesAndTheLowestPerInterface(t *testing.T) {
	table := forwardTable(
		[3]uint32{19, 0, 0},
		[3]uint32{14, 0, 9256},
		[3]uint32{14, 0, 300},
		[3]uint32{19, 24, 1}, // a connected subnet, not a default route
	)
	got := defaultRouteMetrics(table)
	if len(got) != 2 || got[19] != 0 || got[14] != 300 {
		t.Fatalf("got %v", got)
	}
}

func TestDefaultRouteMetricsToleratesATruncatedTable(t *testing.T) {
	table := forwardTable([3]uint32{19, 0, 0}, [3]uint32{14, 0, 5})
	if got := defaultRouteMetrics(table[:forwardTableHeader+forwardRowSize+10]); len(got) != 1 {
		t.Fatalf("got %v", got)
	}
	if got := defaultRouteMetrics(nil); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

// A VPN adapter with a tiny interface metric but a huge default-route metric must lose to the
// physical link, as it does in Windows' own route choice.
func TestTheEffectiveDefaultRouteMetricPicksThePhysicalLink(t *testing.T) {
	adapters := []Adapter{
		{Index: 14, Name: "Radmin VPN", Up: true, HasGateway: true, Metric: 1 + 9256},
		{Index: 19, Name: "Ethernet 2", Up: true, HasGateway: true, Metric: 35 + 0},
	}
	if index, ok := DefaultAdapter(adapters, "skipi0"); !ok || index != 19 {
		t.Fatalf("got %d %v", index, ok)
	}
}
