// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package memstats reads Go runtime memory figures, preferring the lock-free runtime/metrics API.
package memstats

import (
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/metrics"
)

// Stats holds detailed metrics on Go runtime and core memory usage.
type Stats struct {
	AllocBytes    int64  `json:"allocBytes"`
	AllocMb       string `json:"allocMb"`
	TotalAlloc    int64  `json:"totalAlloc"`
	SysBytes      int64  `json:"sysBytes"`
	SysMb         string `json:"sysMb"`
	HeapInuse     int64  `json:"heapInuse"`
	HeapIdle      int64  `json:"heapIdle"`
	HeapReleased  int64  `json:"heapReleased"`
	NumGoroutines int    `json:"numGoroutines"`
	NumGC         uint32 `json:"numGc"`
}

// JSON returns the current memory usage of the Go runtime and tunnel core as a JSON string.
//
// Reads go through the runtime/metrics package, which is effectively
// lock-free: runtime.ReadMemStats would stop the whole Go world on every call,
// and this endpoint is polled periodically by the UI while the tunnel is
// forwarding traffic. A MemStats fallback keeps the JSON contract intact on
// runtimes where a metric is unavailable.
func JSON() string {
	stats := ReadFromMetrics()
	if stats == nil {
		stats = ReadFromMemStats()
	}
	data, err := json.Marshal(stats)
	if err != nil {
		return `{"error":"failed to marshal memory stats"}`
	}
	return string(data)
}

func ReadFromMetrics() *Stats {
	samples := []metrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},  // live heap objects -> AllocBytes
		{Name: "/gc/heap/allocs:bytes"},               // cumulative allocated  -> TotalAlloc
		{Name: "/memory/classes/total:bytes"},         // total runtime memory   -> SysBytes
		{Name: "/memory/classes/heap/free:bytes"},     // idle, not yet returned -> HeapIdle part
		{Name: "/memory/classes/heap/released:bytes"}, // returned to the OS     -> HeapReleased
		{Name: "/gc/cycles/total:gc-cycles"},
		{Name: "/sched/goroutines:goroutines"},
	}
	metrics.Read(samples)
	// Every metric above is a uint64 counter or gauge; anything else (including KindBad for a
	// name this runtime does not know) sends the caller to the MemStats fallback.
	for _, sample := range samples {
		if sample.Value.Kind() != metrics.KindUint64 {
			return nil
		}
	}

	const mb = 1024 * 1024
	heapObjects := int64(samples[0].Value.Uint64())
	totalAlloc := int64(samples[1].Value.Uint64())
	sysBytes := int64(samples[2].Value.Uint64())
	heapFree := int64(samples[3].Value.Uint64())
	heapReleased := int64(samples[4].Value.Uint64())

	return &Stats{
		AllocBytes:    heapObjects,
		AllocMb:       fmt.Sprintf("%.2f MB", float64(heapObjects)/mb),
		TotalAlloc:    totalAlloc,
		SysBytes:      sysBytes,
		SysMb:         fmt.Sprintf("%.2f MB", float64(sysBytes)/mb),
		HeapInuse:     heapObjects,
		HeapIdle:      heapFree + heapReleased,
		HeapReleased:  heapReleased,
		NumGoroutines: int(samples[6].Value.Uint64()),
		NumGC:         uint32(samples[5].Value.Uint64()),
	}
}

func ReadFromMemStats() *Stats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	const mb = 1024 * 1024
	return &Stats{
		AllocBytes:    int64(m.Alloc),
		AllocMb:       fmt.Sprintf("%.2f MB", float64(m.Alloc)/mb),
		TotalAlloc:    int64(m.TotalAlloc),
		SysBytes:      int64(m.Sys),
		SysMb:         fmt.Sprintf("%.2f MB", float64(m.Sys)/mb),
		HeapInuse:     int64(m.HeapInuse),
		HeapIdle:      int64(m.HeapIdle),
		HeapReleased:  int64(m.HeapReleased),
		NumGoroutines: runtime.NumGoroutine(),
		NumGC:         m.NumGC,
	}
}
