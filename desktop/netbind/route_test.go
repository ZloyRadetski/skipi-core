// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package netbind

import "testing"

const header = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"

func TestDefaultInterfacePicksTheLowestMetricDefaultRoute(t *testing.T) {
	table := header +
		"wlp13s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
		"enp12s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"enp12s0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"

	got, ok := DefaultInterface(table, "skipi0")

	if !ok || got != "enp12s0" {
		t.Fatalf("DefaultInterface = %q, %v; want enp12s0, true", got, ok)
	}
}

func TestDefaultInterfaceIgnoresTheTunnelAndHalfRoutes(t *testing.T) {
	table := header +
		"skipi0\t00000000\t00000000\t0001\t0\t0\t50\t80000000\t0\t0\t0\n" +
		"skipi0\t80000000\t00000000\t0001\t0\t0\t50\t80000000\t0\t0\t0\n" +
		"skipi0\t00000000\t0100FEAC\t0003\t0\t0\t10\t00000000\t0\t0\t0\n" +
		"wlp13s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"

	got, ok := DefaultInterface(table, "skipi0")

	if !ok || got != "wlp13s0" {
		t.Fatalf("DefaultInterface = %q, %v; want wlp13s0, true", got, ok)
	}
}

func TestDefaultInterfaceSkipsRoutesThatAreDownOrHaveNoGateway(t *testing.T) {
	table := header +
		"enp12s0\t00000000\t0101A8C0\t0002\t0\t0\t10\t00000000\t0\t0\t0\n" + // gateway but not up
		"tun0\t00000000\t00000000\t0001\t0\t0\t20\t00000000\t0\t0\t0\n" + // up, no gateway flag
		"wlp13s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"

	got, ok := DefaultInterface(table, "skipi0")

	if !ok || got != "wlp13s0" {
		t.Fatalf("DefaultInterface = %q, %v; want wlp13s0, true", got, ok)
	}
}

func TestDefaultInterfaceReportsNoRoute(t *testing.T) {
	if got, ok := DefaultInterface(header, "skipi0"); ok {
		t.Fatalf("empty table gave %q", got)
	}
	if got, ok := DefaultInterface("", "skipi0"); ok {
		t.Fatalf("blank table gave %q", got)
	}
	if got, ok := DefaultInterface(header+"garbage line\n", "skipi0"); ok {
		t.Fatalf("garbage table gave %q", got)
	}
}
