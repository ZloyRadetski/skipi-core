// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package winnet

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/ZloyRadetski/skipi-core/desktop/netbind"
	"golang.org/x/sys/windows"
)

// Without administrator rights the system refuses a route, but it must take our row: a wrong layout is
// ERROR_INVALID_PARAMETER, a lack of rights is ERROR_ACCESS_DENIED.
func TestTheSystemTakesTheRowAndRefusesOnlyForLackOfRights(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("elevated: the next test covers real routes")
	}
	names, err := netbind.AdapterNames()
	if err != nil || len(names) == 0 {
		t.Skip("no adapters to test with")
	}
	luid, err := interfaceLuid(names[0])
	if err != nil {
		t.Skip("cannot resolve " + names[0])
	}
	if luid == 0 {
		t.Fatal("an adapter has a LUID")
	}
	// TEST-NET-1 (RFC 5737) is never routed.
	err = nativeAddRoute(names[0], netip.MustParsePrefix("192.0.2.0/24"))
	if err == nil {
		t.Fatal("a route cannot be created without administrator rights")
	}
	var errno windows.Errno
	if errors.As(err, &errno) && errno == windows.ERROR_INVALID_PARAMETER {
		t.Fatalf("the row layout is wrong: %v", err)
	}
}

func TestARealRouteIsAddedAndRemovedWhenElevated(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs administrator rights")
	}
	names, _ := netbind.AdapterNames()
	loop := ""
	for _, n := range names {
		if n == "Loopback Pseudo-Interface 1" {
			loop = n
		}
	}
	if loop == "" {
		t.Skip("no loopback adapter")
	}
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	if err := nativeAddRoute(loop, prefix); err != nil {
		t.Fatal(err)
	}
	if err := nativeAddRoute(loop, prefix); err != nil {
		t.Fatalf("adding it twice is not an error: %v", err)
	}
	if err := nativeDeleteRoute(loop, prefix); err != nil {
		t.Fatal(err)
	}
	if err := nativeDeleteRoute(loop, prefix); err != nil {
		t.Fatalf("deleting a missing route is not an error: %v", err)
	}
}
