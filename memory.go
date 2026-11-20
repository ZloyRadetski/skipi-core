// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"runtime/debug"

	"github.com/ZloyRadetski/skipi-core/internal/memstats"
)

// MemoryStats holds detailed metrics on Go runtime and core memory usage.
type MemoryStats struct {
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

// The implementation lives in internal/memstats, whose Stats must stay field-for-field the same
// as the bound MemoryStats; this conversion stops compiling when they drift apart.
var _ = MemoryStats(memstats.Stats{})

// ReadMemoryStats returns the current memory usage of the Go runtime and tunnel core as a JSON string.
//
// Reads go through the runtime/metrics package, which is effectively
// lock-free: runtime.ReadMemStats would stop the whole Go world on every call,
// and this endpoint is polled periodically by the UI while the tunnel is
// forwarding traffic. A MemStats fallback keeps the JSON contract intact on
// runtimes where a metric is unavailable.
func ReadMemoryStats() string {
	return memstats.JSON()
}

// releaseMemory collects and hands freed memory back to the OS. Core runs it in the background
// after a start (the parsed config and geo data are garbage then) and after a stop (the whole
// instance is). A variable so tests can count it.
var releaseMemory = debug.FreeOSMemory

// ForceFreeMemory triggers a garbage collection cycle and releases unused memory back to the OS.
func ForceFreeMemory() {
	debug.FreeOSMemory()
}
