// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package connlog

import (
	"strconv"
	"testing"
)

func BenchmarkRecordRouted(b *testing.B) {
	l := New(true)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		id := strconv.Itoa(i)
		l.Record("2026/11/21 10:00:00 [Info] [" + id + "] app/dispatcher: sniffed domain: example.com")
		l.Record("2026/11/21 10:00:00 from tcp:127.0.0.1:5555 accepted tcp:93.184.216.34:443 [inbound >> proxy] [" + id + "] taking detour [proxy] for [tcp:example.com:443]")
	}
}

func BenchmarkRecordIgnoredLine(b *testing.B) {
	l := New(true)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		l.Record("2026/11/21 10:00:00 [Info] transport/internet/tcp: dialing TCP to tcp:93.184.216.34:443")
	}
}

func BenchmarkSnapshot(b *testing.B) {
	l := New(true)
	for i := 0; i < 1500; i++ {
		id := strconv.Itoa(i)
		l.Record("[" + id + "] taking detour [proxy] for [tcp:example.com:443]")
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = l.Snapshot(0)
	}
}
