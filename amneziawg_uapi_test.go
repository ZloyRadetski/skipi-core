// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"strings"
	"testing"
)

// C8: the UAPI config is line based, so a value carrying a line break would add settings of its
// own (another peer, an endpoint). Every value is checked, and a pre-shared key that does not
// decode fails the start instead of bringing the tunnel up without it.

func ipcSettings(mut func(s *AmneziaWgSettings)) *AmneziaWgSettings {
	s := &AmneziaWgSettings{
		SecretKey: "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=",
		Peers: []*AmneziaWgPeer{{
			PublicKey:  "YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=",
			Endpoint:   "192.0.2.1:51820",
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		}},
	}
	if mut != nil {
		mut(s)
	}
	return s
}

func TestIpcConfigRefusesValuesThatWouldAddLines(t *testing.T) {
	cases := map[string]func(s *AmneziaWgSettings){
		"allowed ip newline": func(s *AmneziaWgSettings) {
			s.Peers[0].AllowedIPs = []string{"0.0.0.0/0\npublic_key=" + strings.Repeat("ab", 32)}
		},
		"allowed ip cr":      func(s *AmneziaWgSettings) { s.Peers[0].AllowedIPs = []string{"0.0.0.0/0\rx=y"} },
		"allowed ip garbage": func(s *AmneziaWgSettings) { s.Peers[0].AllowedIPs = []string{"everything"} },
		"endpoint newline":   func(s *AmneziaWgSettings) { s.Peers[0].Endpoint = "192.0.2.1:51820\nendpoint=198.51.100.1:1" },
		"h1 newline":         func(s *AmneziaWgSettings) { s.H1 = "1\nlisten_port=1" },
		"i1 newline":         func(s *AmneziaWgSettings) { s.I1 = "<b 0x01>\nprivate_key=00" },
	}
	for name, mut := range cases {
		if out, err := ipcSettings(mut).BuildIpcConfig(); err == nil {
			t.Errorf("%s accepted:\n%s", name, out)
		}
	}
}

func TestIpcConfigRefusesAPreSharedKeyThatDoesNotDecode(t *testing.T) {
	s := ipcSettings(func(s *AmneziaWgSettings) { s.Peers[0].PreSharedKey = "not a key!" })
	if out, err := s.BuildIpcConfig(); err == nil {
		t.Fatalf("a broken pre-shared key must fail the start, got:\n%s", out)
	}
}

func TestIpcConfigKeepsValidValues(t *testing.T) {
	s := ipcSettings(func(s *AmneziaWgSettings) {
		s.Peers[0].PreSharedKey = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE="
		s.Peers[0].AllowedIPs = []string{"10.0.0.0/8", " 192.168.0.0/16 ", "fd00::/8"}
	})
	out, err := s.BuildIpcConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"preshared_key=", "allowed_ip=10.0.0.0/8\n", "allowed_ip=192.168.0.0/16\n", "allowed_ip=fd00::/8\n", "endpoint=192.0.2.1:51820\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
