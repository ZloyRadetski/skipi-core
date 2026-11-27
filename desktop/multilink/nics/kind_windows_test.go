// Based on net-merge (https://github.com/net-merge/net-merge), Copyright (c) 2026 Rohit Mahto, MIT License;
// see third_party/net-merge. Changes for SKIPI Core: Copyright 2026, Radetski, GPL-3.0.

package nics

import "testing"

func TestWindowsAdapterPresentationTypes(t *testing.T) {
	for _, tc := range []struct {
		ifType uint32
		desc   string
		want   Kind
	}{
		{71, "Intel Wi-Fi", WiFi}, {6, "Realtek GbE", Ethernet},
		{6, "Apple Mobile Device Ethernet", Phone}, {6, "Remote NDIS Internet Sharing Device", Phone},
		{243, "Mobile broadband", Phone}, {131, "Tunnel", Unknown},
		// A Bluetooth network says it is Ethernet; it must not get the network-cable icon.
		{6, "Bluetooth Device (Personal Area Network)", Unknown},
	} {
		if got := windowsKind(tc.ifType, tc.desc); got != tc.want {
			t.Errorf("%d %q: %s, want %s", tc.ifType, tc.desc, got, tc.want)
		}
	}
}
