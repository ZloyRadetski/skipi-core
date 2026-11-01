// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package netbind

import "testing"

const netstatHeader = "Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\n"

func TestNetstatDefaultInterfacePicksThePrimaryDefaultRoute(t *testing.T) {
	table := netstatHeader +
		"default            192.168.1.1        UGScg                 en0       \n" +
		"default            10.0.0.1           UGScIg                en1       \n" +
		"127                127.0.0.1          UCS                   lo0       \n" +
		"192.168.1/24       link#6             UCS                   en0      !\n"

	got, ok := DefaultInterfaceFromNetstat(table, "utun9")

	if !ok || got != "en0" {
		t.Fatalf("DefaultInterfaceFromNetstat = %q, %v; want en0, true", got, ok)
	}
}

func TestNetstatDefaultInterfaceNeverChoosesTunnelInterfaces(t *testing.T) {
	table := netstatHeader +
		"default            link#18            UCSIg               utun4       \n" +
		"default            10.8.0.1           UGScg               utun9       \n" +
		"default            192.168.1.1        UGScIg                en0       \n"

	got, ok := DefaultInterfaceFromNetstat(table, "utun9")

	if !ok || got != "en0" {
		t.Fatalf("DefaultInterfaceFromNetstat = %q, %v; want en0, true", got, ok)
	}
}

func TestNetstatDefaultInterfaceIgnoresTheHalfRoutesTheTunnelInstalls(t *testing.T) {
	table := netstatHeader +
		"0/1                10.8.0.1           UGSc                utun9       \n" +
		"128.0/1            10.8.0.1           UGSc                utun9       \n" +
		"default            192.168.1.1        UGScg                 en0       \n"

	got, ok := DefaultInterfaceFromNetstat(table, "utun9")

	if !ok || got != "en0" {
		t.Fatalf("DefaultInterfaceFromNetstat = %q, %v; want en0, true", got, ok)
	}
}

func TestNetstatDefaultInterfaceNeedsAGatewayAndAnUpRoute(t *testing.T) {
	table := netstatHeader +
		"default            link#6             UCSg                  en0       \n" + // on-link, no gateway address
		"default            192.168.1.1        GScg                  en1       \n" + // not up
		"default            192.168.5.1        UGScg                 en2       \n"

	got, ok := DefaultInterfaceFromNetstat(table, "utun9")

	if !ok || got != "en2" {
		t.Fatalf("DefaultInterfaceFromNetstat = %q, %v; want en2, true", got, ok)
	}
}

func TestNetstatDefaultInterfaceReportsNoRoute(t *testing.T) {
	for _, table := range []string{"", netstatHeader, netstatHeader + "garbage line\n"} {
		if got, ok := DefaultInterfaceFromNetstat(table, "utun9"); ok {
			t.Fatalf("table %q gave %q", table, got)
		}
	}
}
