// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hevtun

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

// C2: hev runs commands from post-up-script/pre-down-script and writes wherever log-file and
// pid-file point. On macOS it runs as root and on Windows with Core's rights, so Core lets only
// known keys through to it.

const appYAML = `tunnel:
  name: 'utun9'
  mtu: 1500
  multi-queue: true
  ipv4: '198.18.0.1'
  ipv6: 'fc00::1'
socks5:
  port: 10808
  address: '127.0.0.1'
  udp: 'udp'
  username: 'u'
  password: 'p''w'
  tcp-fastopen: true
misc:
  tcp-read-write-timeout: 300000
  udp-read-write-timeout: 60000
  log-file: '/data/user/0/app/cache/hev.log'
  log-level: warn
`

func decode(t *testing.T, text string) map[string]map[string]any {
	t.Helper()
	var out map[string]map[string]any
	if err := yaml.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("%v in:\n%s", err, text)
	}
	return out
}

func TestTheAppsConfigPassesUnchangedInProcess(t *testing.T) {
	got, err := SanitizeConfig(appYAML, true)
	if err != nil {
		t.Fatal(err)
	}
	if want, have := decode(t, appYAML), decode(t, got); !equalYAML(want, have) {
		t.Fatalf("want %v\nhave %v", want, have)
	}
}

func TestProcessModesDropTheLogFile(t *testing.T) {
	got, err := SanitizeConfig(appYAML, false)
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, got)
	if _, ok := m["misc"]["log-file"]; ok {
		t.Fatalf("log-file reached a privileged hev:\n%s", got)
	}
	if m["misc"]["log-level"] != "warn" || m["socks5"]["password"] != "p'w" || m["tunnel"]["ipv4"] != "198.18.0.1" {
		t.Fatalf("other values must survive:\n%s", got)
	}
}

func TestScriptsAndPidFileAreRefusedEverywhere(t *testing.T) {
	cases := map[string]string{
		"post-up":   "tunnel:\n  mtu: 1500\n  post-up-script: /tmp/x.sh\n",
		"pre-down":  "tunnel:\n  mtu: 1500\n  pre-down-script: 'touch /etc/x'\n",
		"pid-file":  "misc:\n  pid-file: /etc/sudoers\n",
		"elsewhere": "socks5:\n  post-up-script: /tmp/x.sh\n",
	}
	for name, text := range cases {
		for _, inProcess := range []bool{true, false} {
			if _, err := SanitizeConfig(text, inProcess); err == nil {
				t.Errorf("%s (in process %v) accepted", name, inProcess)
			}
		}
	}
}

func TestUnknownKeysAndShapesAreRefused(t *testing.T) {
	cases := map[string]string{
		"unknown top":     "shell:\n  cmd: x\n",
		"unknown nested":  "tunnel:\n  exec: x\n",
		"nested map":      "tunnel:\n  name:\n    post-up-script: x\n",
		"list value":      "tunnel:\n  ipv4: [a, b]\n",
		"section scalar":  "tunnel: 1\n",
		"duplicate key":   "tunnel:\n  mtu: 1\ntunnel:\n  post-up-script: x\n",
		"duplicate inner": "tunnel:\n  mtu: 1\n  mtu: 2\n",
		"not yaml":        "tunnel: [",
		"top list":        "- a\n",
		"empty":           "",
		"non-string key":  "tunnel:\n  1: x\n",
	}
	for name, text := range cases {
		if _, err := SanitizeConfig(text, true); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestMapDNSIsAllowed(t *testing.T) {
	text := "tunnel:\n  mtu: 1500\nmapdns:\n  address: 198.18.0.2\n  port: 53\n  network: 100.64.0.0\n  netmask: 255.192.0.0\n  cache-size: 10000\n"
	if _, err := SanitizeConfig(text, false); err != nil {
		t.Fatal(err)
	}
}

func TestTheRefusalNamesTheKey(t *testing.T) {
	_, err := SanitizeConfig("tunnel:\n  post-up-script: x\n", false)
	if err == nil || !strings.Contains(err.Error(), "tunnel.post-up-script") {
		t.Fatalf("err = %v", err)
	}
}

func equalYAML(a, b map[string]map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || len(av) != len(bv) {
			return false
		}
		for kk, v := range av {
			if bv[kk] != v {
				return false
			}
		}
	}
	return true
}

// hev 2.20.0 added the Windows Wintun ring size to misc: a number, harmless, so it may pass.
func TestTheWintunRingCapacityIsAllowed(t *testing.T) {
	got, err := SanitizeConfig("misc:\n  wintun-ring-capacity: 1048576\n", false)
	if err != nil {
		t.Fatal(err)
	}
	if m := decode(t, got); m["misc"]["wintun-ring-capacity"] != 1048576 {
		t.Fatalf("got %s", got)
	}
}
