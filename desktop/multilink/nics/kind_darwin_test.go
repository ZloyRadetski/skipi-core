// Based on net-merge (https://github.com/net-merge/net-merge), Copyright (c) 2026 Rohit Mahto, MIT License;
// see third_party/net-merge. Changes for SKIPI Core: Copyright 2026, Radetski, GPL-3.0.

package nics

import "testing"

func TestMacHardwarePortPresentationTypes(t *testing.T) {
	for _, tc := range []struct {
		name, port string
		want       Kind
	}{
		{"en0", "Wi-Fi", WiFi}, {"en1", "USB 10/100/1000 LAN", Ethernet},
		{"en2", "iPhone USB", Phone}, {"feth0", "", Phone}, {"utun0", "", Unknown},
	} {
		if got := darwinKind(tc.name, tc.port); got != tc.want {
			t.Errorf("%s %q: %s, want %s", tc.name, tc.port, got, tc.want)
		}
	}
}
