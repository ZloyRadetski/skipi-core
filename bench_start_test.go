// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// BenchmarkStartLoopWithGeoRules times a full start and stop of Xray with routing rules that need
// the geo files. It needs SKIPI_BENCH_GEO, a folder holding geoip.dat and geosite.dat.
func BenchmarkStartLoopWithGeoRules(b *testing.B) {
	dir := os.Getenv("SKIPI_BENCH_GEO")
	if dir == "" {
		b.Skip("SKIPI_BENCH_GEO is not set")
	}
	InitCoreEnv(dir, "")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	config := fmt.Sprintf(`{
	  "log": {"loglevel": "none"},
	  "inbounds": [{"tag":"socks","listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"udp":false}}],
	  "outbounds": [{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],
	  "routing": {"domainStrategy":"IPIfNonMatch","rules":[
	    {"type":"field","domain":["geosite:category-ads-all"],"outboundTag":"block"},
	    {"type":"field","domain":["geosite:cn","geosite:google","geosite:youtube"],"outboundTag":"direct"},
	    {"type":"field","ip":["geoip:private","geoip:cn","geoip:ru"],"outboundTag":"direct"}
	  ]}}`, port)

	c := NewCoreController(nil)
	var total time.Duration
	for i := 0; i < b.N; i++ {
		start := time.Now()
		if err := c.StartLoop(config, 0); err != nil {
			b.Fatal(err)
		}
		total += time.Since(start)
		if err := c.StopLoop(); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(total.Milliseconds())/float64(b.N), "start_ms")
}
