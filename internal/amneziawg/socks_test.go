package amneziawg

import (
	"net"
	"net/netip"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

func TestAmneziaWgUDPBindAddressSelectsConfiguredLocalFamily(t *testing.T) {
	localAddrs := []netip.Addr{
		netip.MustParseAddr("10.125.77.96"),
		netip.MustParseAddr("fd00::96"),
	}
	tests := []struct {
		name        string
		destination *net.UDPAddr
		wantFamily  string
		wantIP      net.IP
	}{
		{
			name:        "ipv4",
			destination: &net.UDPAddr{IP: net.ParseIP("198.51.100.25"), Port: 53},
			wantFamily:  "ipv4",
			wantIP:      net.ParseIP("10.125.77.96"),
		},
		{
			name:        "ipv6",
			destination: &net.UDPAddr{IP: net.ParseIP("2001:db8::53"), Port: 53},
			wantFamily:  "ipv6",
			wantIP:      net.ParseIP("fd00::96"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bind, family, err := UDPBindAddress(test.destination, localAddrs)
			if err != nil {
				t.Fatalf("amneziaWgUDPBindAddress failed: %v", err)
			}
			if family != test.wantFamily {
				t.Fatalf("expected family %q, got %q", test.wantFamily, family)
			}
			if bind.Port != 0 || !bind.IP.Equal(test.wantIP) {
				t.Fatalf("unexpected bind address %v", bind)
			}
		})
	}

	if _, _, err := UDPBindAddress(nil, localAddrs); err == nil {
		t.Fatal("expected missing destination to be rejected before netstack access")
	}
	if _, _, err := UDPBindAddress(
		&net.UDPAddr{IP: net.ParseIP("2001:db8::53"), Port: 53},
		[]netip.Addr{netip.MustParseAddr("10.125.77.96")},
	); err == nil {
		t.Fatal("expected an IPv6 destination without an IPv6 tunnel address to be rejected")
	}
}

func TestAmneziaWgUDPBindAddressCreatesUsableNetstackEndpoints(t *testing.T) {
	localAddrs := []netip.Addr{
		netip.MustParseAddr("10.125.77.96"),
		netip.MustParseAddr("fd00::96"),
	}
	device, tnet, err := netstack.CreateNetTUN(localAddrs, nil, 1280)
	if err != nil {
		t.Fatalf("CreateNetTUN failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	for _, destination := range []*net.UDPAddr{
		{IP: net.ParseIP("198.51.100.25"), Port: 53},
		{IP: net.ParseIP("2001:db8::53"), Port: 53},
	} {
		bind, _, err := UDPBindAddress(destination, localAddrs)
		if err != nil {
			t.Fatalf("amneziaWgUDPBindAddress failed: %v", err)
		}
		conn, err := tnet.ListenUDP(bind)
		if err != nil {
			t.Fatalf("ListenUDP(%v) failed: %v", bind, err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("Close UDP endpoint failed: %v", err)
		}
	}
}
