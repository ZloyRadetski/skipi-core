// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"encoding/json"
	"testing"
)

func TestConnectionLogJoinsSniffedNameWithRoute(t *testing.T) {
	l := newConnectionLog(true)
	l.record("[Info] [42] dispatcher: sniffed domain: example.test")
	l.record("[Info] [42] dispatcher: taking detour [proxy] for [tcp:1.2.3.4:443]")
	l.record("[Info] [43] dispatcher: default route for udp:[2001:db8::1]:53")
	l.record("[Info] [44] dispatcher: Hit route rule: [r] so taking detour [direct] for [tcp:a.test:80]")

	var s connectionLogSnapshot
	if err := json.Unmarshal([]byte(l.snapshot(0)), &s); err != nil {
		t.Fatal(err)
	}
	want := []ConnectionLogEntry{
		{Seq: 1, Host: "example.test", Port: 443, Network: "tcp", Outbound: "proxy"},
		{Seq: 2, Host: "2001:db8::1", Port: 53, Network: "udp", Outbound: "default"},
		{Seq: 3, Host: "a.test", Port: 80, Network: "tcp", Outbound: "direct"},
	}
	if len(s.Entries) != len(want) || s.Seq != 3 {
		t.Fatalf("got %+v", s)
	}
	for i, e := range s.Entries {
		w := want[i]
		if e.Seq != w.Seq || e.Host != w.Host || e.Port != w.Port || e.Network != w.Network || e.Outbound != w.Outbound {
			t.Fatalf("entry %d: got %+v want %+v", i, e, w)
		}
	}
	var after connectionLogSnapshot
	_ = json.Unmarshal([]byte(l.snapshot(2)), &after)
	if len(after.Entries) != 1 || after.Entries[0].Seq != 3 {
		t.Fatalf("after: %+v", after)
	}
}

func TestConnectionLogOffRecordsNothing(t *testing.T) {
	l := newConnectionLog(false)
	l.record("[Info] [1] dispatcher: default route for tcp:1.2.3.4:443")
	if l.snapshot(0) != `{"seq":0,"entries":[]}` {
		t.Fatal(l.snapshot(0))
	}
}
