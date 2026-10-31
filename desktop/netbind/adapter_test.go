// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package netbind

import "testing"

func TestDefaultAdapterPicksTheLowestMetricUpAdapterWithAGateway(t *testing.T) {
	adapters := []Adapter{
		{Index: 12, Name: "Ethernet 3", Up: true, HasGateway: true, Metric: 50},
		{Index: 19, Name: "Ethernet 2", Up: true, HasGateway: true, Metric: 25},
		{Index: 15, Name: "Wi-Fi", Up: true, HasGateway: true, Metric: 40},
	}

	index, ok := DefaultAdapter(adapters, "skipi0")

	if !ok || index != 19 {
		t.Fatalf("DefaultAdapter = %d, %v", index, ok)
	}
}

func TestDefaultAdapterSkipsTheTunnelDownLoopbackAndGatewaylessAdapters(t *testing.T) {
	adapters := []Adapter{
		{Index: 30, Name: "SKIPI0", Up: true, HasGateway: true, Metric: 1},
		{Index: 31, Name: "Wi-Fi", Up: false, HasGateway: true, Metric: 2},
		{Index: 1, Name: "Loopback", Up: true, HasGateway: true, Metric: 3, Loopback: true},
		{Index: 32, Name: "Radmin", Up: true, HasGateway: false, Metric: 4},
		{Index: 33, Name: "Ethernet", Up: true, HasGateway: true, Metric: 90},
	}

	index, ok := DefaultAdapter(adapters, "skipi0")

	if !ok || index != 33 {
		t.Fatalf("DefaultAdapter = %d, %v (the tunnel name is matched ignoring case)", index, ok)
	}
}

func TestDefaultAdapterBreaksMetricTiesByTheLowerIndex(t *testing.T) {
	adapters := []Adapter{
		{Index: 20, Name: "B", Up: true, HasGateway: true, Metric: 10},
		{Index: 8, Name: "A", Up: true, HasGateway: true, Metric: 10},
	}

	if index, ok := DefaultAdapter(adapters, ""); !ok || index != 8 {
		t.Fatalf("DefaultAdapter = %d, %v", index, ok)
	}
}

func TestDefaultAdapterReportsNothingWithoutAPhysicalDefaultRoute(t *testing.T) {
	if _, ok := DefaultAdapter(nil, "skipi0"); ok {
		t.Fatal("no adapters must not yield a choice")
	}
	if _, ok := DefaultAdapter([]Adapter{{Index: 5, Name: "Wi-Fi", Up: false, HasGateway: true}}, "skipi0"); ok {
		t.Fatal("a down adapter must not be chosen")
	}
}

func TestUnicastIfValueV4IsTheInterfaceIndexInNetworkByteOrder(t *testing.T) {
	if got := UnicastIfValueV4(19); got != 0x13000000 {
		t.Fatalf("UnicastIfValueV4(19) = %#x", got)
	}
	if got := UnicastIfValueV4(0x01020304); got != 0x04030201 {
		t.Fatalf("UnicastIfValueV4 = %#x", got)
	}
}
