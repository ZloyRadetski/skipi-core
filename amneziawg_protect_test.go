// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"context"
	"net/netip"
	"strings"
	"syscall"
	"testing"
)

// C6: where Core runs inside a VPN (Android), a runner without a protector would send its peer
// traffic into the tunnel it carries; it must not start silently.
func TestAndroidRunnerRefusesToStartWithoutAProtector(t *testing.T) {
	defer func(old bool) { requireAwgProtector = old }(requireAwgProtector)
	requireAwgProtector = true
	SetAmneziaWgSocketProtector(nil)
	settings, err := ParseAmneziaWgSettings(`{"secretKey":"aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=","address":["10.8.0.2/32"],"dnsServers":["1.1.1.1"],
	"peers":[{"publicKey":"YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=","endpoint":"127.0.0.1:59999","allowedIPs":["0.0.0.0/0"]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAmneziaWgRunner(settings, 0); err == nil || !strings.Contains(err.Error(), "protect") {
		t.Fatalf("err = %v", err)
	}
}

// C6: with a protector the peer's name is looked up through the configured DNS over a protected
// socket first; the system resolver, whose queries may enter the tunnel, is only the fallback.
func TestPeerLookupUsesTheProtectedConfiguredDNSFirst(t *testing.T) {
	var order []string
	var gotControl bool
	origSystem, origConfigured := systemHostLookup, configuredHostLookup
	defer func() { systemHostLookup, configuredHostLookup = origSystem, origConfigured }()
	systemHostLookup = func(context.Context, string) ([]netip.Addr, error) {
		order = append(order, "system")
		return []netip.Addr{netip.MustParseAddr("198.51.100.1")}, nil
	}
	configuredHostLookup = func(_ context.Context, _ string, _ []netip.Addr, control func(string, string, syscall.RawConn) error) ([]netip.Addr, error) {
		order = append(order, "configured")
		gotControl = control != nil
		return []netip.Addr{netip.MustParseAddr("198.51.100.2")}, nil
	}

	s := ipcSettings(func(s *AmneziaWgSettings) { s.Peers[0].Endpoint = "relay.example:51820" })
	if err := s.resolvePeerEndpoints([]netip.Addr{netip.MustParseAddr("1.1.1.1")}, &dummySocketProtector{}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "configured" || !gotControl || s.Peers[0].Endpoint != "198.51.100.2:51820" {
		t.Fatalf("order = %v, control = %v, endpoint = %s", order, gotControl, s.Peers[0].Endpoint)
	}

	order = nil
	s = ipcSettings(func(s *AmneziaWgSettings) { s.Peers[0].Endpoint = "relay.example:51820" })
	if err := s.resolvePeerEndpoints([]netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "system" {
		t.Fatalf("without a protector the system resolver keeps going first: %v", order)
	}
}
