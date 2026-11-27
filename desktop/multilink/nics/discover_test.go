// Based on net-merge (https://github.com/net-merge/net-merge), Copyright (c) 2026 Rohit Mahto, MIT License;
// see third_party/net-merge. Changes for SKIPI Core: Copyright 2026, Radetski, GPL-3.0.

//go:build !android

package nics

import (
	"net"
	"testing"
)

func TestIsPhoneFindsAnIPhoneHotspot(t *testing.T) {
	for _, c := range []struct {
		ip   string
		bits int
		desc string
		want bool
	}{
		{"172.20.10.2", 28, "", true},                 // Personal Hotspot over Wi-Fi: only the address tells
		{"172.20.10.14", 28, "Wi-Fi", true},           // the last address of the /28
		{"", 0, "iPhone USB", true},                   // macOS, before DHCP
		{"", 0, "Apple Mobile Device Ethernet", true}, // Windows
		{"", 0, "ipheth", true},                       // Linux driver
		{"172.20.10.5", 16, "Wi-Fi", false},           // an office or campus network on 172.20.0.0/16
		{"172.20.10.5", 24, "Ethernet", false},        // a /24 that happens to sit there
		{"172.20.10.16", 28, "Wi-Fi", false},          // next door to the /28
		{"192.168.1.20", 24, "Wi-Fi", false},
		{"172.20.11.2", 28, "Ethernet", false},
		{"10.0.0.5", 8, "r8169", false},
		{"", 0, "", false},
	} {
		if got := isPhone(net.ParseIP(c.ip).To4(), c.bits, c.desc); got != c.want {
			t.Errorf("isPhone(%q, /%d, %q) = %v, want %v", c.ip, c.bits, c.desc, got, c.want)
		}
	}
}
