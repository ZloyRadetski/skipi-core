// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package runtimetuning applies the mobile-first Go runtime profile (GC percent, memory
// limit, GOMAXPROCS) and the temporary GC pause used while a core loads its data.
package runtimetuning

import (
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
)

// ResolveMaxProcs picks how many OS threads may run Go code at once.
//
// The core shares a process (and the CPU's few big cores) with the UI. Letting Go use every
// core makes a tunnel start or a heavy download compete with the UI thread and shows up as
// dropped frames; proxy forwarding is I/O bound, so half the cores is plenty. The result is
// never below 2 (or the CPU count on a single-core device) and an explicit override in
// 1..numCPU wins.
func ResolveMaxProcs(numCPU int, override string) int {
	if numCPU < 1 {
		numCPU = 1
	}
	if parsed, err := strconv.Atoi(override); err == nil && parsed >= 1 {
		if parsed > numCPU {
			return numCPU
		}
		return parsed
	}
	procs := (numCPU + 1) / 2
	if procs < 2 {
		procs = 2
	}
	if procs > numCPU {
		procs = numCPU
	}
	return procs
}

var (
	gcPauseMu       sync.Mutex
	gcPauseHolders  int
	gcPausePrevious int
)

// PauseGCForStartup disables the periodic GC for the duration of a core start. Parsing the
// routing rules and geo data allocates a large burst of long-lived memory; with the low GOGC
// used for steady state the collector would rescan that growing heap again and again on every
// core while the UI is trying to animate. The soft memory limit stays active as the safety
// net. The returned function is idempotent; the previous percentage returns once the last
// concurrent holder has restored.
func PauseGCForStartup() func() {
	gcPauseMu.Lock()
	if gcPauseHolders == 0 {
		gcPausePrevious = debug.SetGCPercent(-1)
	}
	gcPauseHolders++
	gcPauseMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			gcPauseMu.Lock()
			defer gcPauseMu.Unlock()
			gcPauseHolders--
			if gcPauseHolders == 0 {
				debug.SetGCPercent(gcPausePrevious)
			}
		})
	}
}

func ApplyMaxProcs() {
	runtime.GOMAXPROCS(ResolveMaxProcs(runtime.NumCPU(), os.Getenv("SKIPI_GOMAXPROCS")))
}

// Init applies the mobile-first runtime profile before any core starts:
//   - GOGC 50 keeps the live heap tighter than the Go default (100), which
//     matters on Android where a fat Go heap invites the low-memory killer.
//     Proxy forwarding is I/O bound, so the extra minor-cycle CPU cost is
//     negligible next to the stability gain.
//   - A soft memory limit acts purely as a safety net: it only starts forcing
//     GC once total runtime memory approaches the ceiling, preventing runaway
//     growth under connection bursts from turning into an OOM kill.
//
// Both values can be overridden per install via SKIPI_GOGC and
// SKIPI_GOMEMLIMIT (bytes) environment variables.
func Init() {
	gcPercent := 50
	if raw := os.Getenv("SKIPI_GOGC"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			gcPercent = parsed
		}
	}
	debug.SetGCPercent(gcPercent)

	const defaultMemoryLimitBytes = 256 << 20 // 256 MiB soft ceiling
	memoryLimit := int64(defaultMemoryLimitBytes)
	if raw := os.Getenv("SKIPI_GOMEMLIMIT"); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			memoryLimit = parsed
		}
	}
	debug.SetMemoryLimit(memoryLimit)
	ApplyMaxProcs()
}
