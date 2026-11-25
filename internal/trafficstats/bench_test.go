// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package trafficstats

import (
	"strconv"
	"testing"
)

func BenchmarkSnapshotAndEncode(b *testing.B) {
	totals := map[string]int64{}
	for i := 0; i < 25; i++ {
		tag := "node-" + strconv.Itoa(i)
		totals["outbound>>>"+tag+">>>traffic>>>uplink"] = int64(1000 + i)
		totals["outbound>>>"+tag+">>>traffic>>>downlink"] = int64(9000 + i)
	}
	totals["inbound>>>socks>>>traffic>>>uplink"] = 5
	totals["inbound>>>socks>>>traffic>>>downlink"] = 7
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Encode(SnapshotFromTotals(totals))
	}
}
