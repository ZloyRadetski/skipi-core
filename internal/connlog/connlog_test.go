// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package connlog

import (
	"encoding/json"
	"testing"
)

func TestConnectionLogJoinsSniffedNameWithRoute(t *testing.T) {
	l := New(true)
	l.Record("[Info] [42] dispatcher: sniffed domain: example.test")
	l.Record("[Info] [42] dispatcher: taking detour [proxy] for [tcp:1.2.3.4:443]")
	l.Record("[Info] [43] dispatcher: default route for udp:[2001:db8::1]:53")
	l.Record("[Info] [44] dispatcher: Hit route rule: [r] so taking detour [direct] for [tcp:a.test:80]")

	var s snapshotJSON
	if err := json.Unmarshal([]byte(l.Snapshot(0)), &s); err != nil {
		t.Fatal(err)
	}
	want := []Entry{
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
	var after snapshotJSON
	_ = json.Unmarshal([]byte(l.Snapshot(2)), &after)
	if len(after.Entries) != 1 || after.Entries[0].Seq != 3 {
		t.Fatalf("after: %+v", after)
	}
}

func TestConnectionLogOffRecordsNothing(t *testing.T) {
	l := New(false)
	l.Record("[Info] [1] dispatcher: default route for tcp:1.2.3.4:443")
	if l.Snapshot(0) != `{"seq":0,"entries":[]}` {
		t.Fatal(l.Snapshot(0))
	}
}
