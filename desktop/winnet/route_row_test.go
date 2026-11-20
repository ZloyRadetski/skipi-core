// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package winnet

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// MIB_IPFORWARD_ROW2 is 104 bytes on a 64-bit Windows; the fields sit where iphlpapi.h puts them.
func TestAnIpv4RouteRowHasEveryFieldWhereWindowsReadsIt(t *testing.T) {
	row, err := encodeRouteRow(0xAABBCCDD11223344, netip.MustParsePrefix("128.0.0.0/1"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(row) != 104 {
		t.Fatalf("size = %d", len(row))
	}
	le := binary.LittleEndian
	if le.Uint64(row[0:]) != 0xAABBCCDD11223344 {
		t.Fatal("InterfaceLuid")
	}
	if le.Uint16(row[12:]) != 2 || row[16] != 128 || row[17] != 0 { // AF_INET, address at +4 of the SOCKADDR_IN
		t.Fatalf("DestinationPrefix.Prefix: % x", row[12:40])
	}
	if row[40] != 1 {
		t.Fatalf("PrefixLength = %d", row[40])
	}
	if le.Uint16(row[44:]) != 2 {
		t.Fatalf("NextHop family = %d, an on-link route needs the unspecified address of its family", le.Uint16(row[44:]))
	}
	if le.Uint32(row[76:]) != 0xFFFFFFFF || le.Uint32(row[80:]) != 0xFFFFFFFF {
		t.Fatal("lifetimes must be infinite")
	}
	if le.Uint32(row[84:]) != 1 {
		t.Fatalf("Metric = %d", le.Uint32(row[84:]))
	}
	if le.Uint32(row[88:]) != 3 {
		t.Fatalf("Protocol = %d, want MIB_IPPROTO_NETMGMT", le.Uint32(row[88:]))
	}
}

func TestAnIpv6RouteRowUsesTheSockaddrIn6Layout(t *testing.T) {
	row, err := encodeRouteRow(1, netip.MustParsePrefix("8000::/1"), 1)
	if err != nil {
		t.Fatal(err)
	}
	le := binary.LittleEndian
	if le.Uint16(row[12:]) != 23 || row[12+8] != 0x80 { // AF_INET6, address at +8 of the SOCKADDR_IN6
		t.Fatalf("DestinationPrefix.Prefix: % x", row[12:40])
	}
	if row[40] != 1 || le.Uint16(row[44:]) != 23 {
		t.Fatalf("prefix length %d, next hop family %d", row[40], le.Uint16(row[44:]))
	}
}

func TestARouteRowNeedsAValidPrefix(t *testing.T) {
	if _, err := encodeRouteRow(1, netip.Prefix{}, 1); err == nil {
		t.Fatal("an empty prefix must be refused")
	}
}

func TestParsePrefixAcceptsThePlansRoutes(t *testing.T) {
	for _, ok := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		if _, err := netip.ParsePrefix(ok); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
}

// ---- native routes with the netsh fallback --------------------------------------------------------

type fakeRoutes struct {
	added, deleted []string
	addErr         error
}

func (f *fakeRoutes) add(name string, prefix netip.Prefix) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.added = append(f.added, name+" "+prefix.String())
	return nil
}

func (f *fakeRoutes) del(name string, prefix netip.Prefix) error {
	f.deleted = append(f.deleted, name+" "+prefix.String())
	return nil
}

func nativeNet(r *recorder, routes *fakeRoutes) *Net {
	return New(Config{
		Run:           r.run,
		AdapterExists: func(string) bool { return true },
		AddRoute:      routes.add,
		DeleteRoute:   routes.del,
		Sleep:         func(time.Duration) {},
		Attempts:      1,
		Serial:        true,
		Background:    func(f func()) { f() },
	})
}
