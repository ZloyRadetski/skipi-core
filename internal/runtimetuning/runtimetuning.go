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

// KeepDefault in a ResolveProfile result leaves that Go runtime setting as it is.
const KeepDefault = -1

const (
	mobileGCPercent   = 50
	mobileMemoryLimit = 256 << 20 // 256 MiB soft ceiling
)

// ResolveProfile picks the GC percent and soft memory limit for goos:
//   - On a phone (android, ios) GOGC 50 keeps the live heap tighter than the Go default (100),
//     which matters where a fat Go heap invites the low-memory killer, and a 256 MiB soft limit
//     is a safety net against runaway growth under connection bursts.
//   - On a desktop both stay at the Go defaults: a large heap is normal there, and the limit
//     would keep the collector running all the time.
//
// SKIPI_GOGC and SKIPI_GOMEMLIMIT (bytes), read through env, override either value everywhere.
func ResolveProfile(goos string, env func(string) string) (gcPercent int, memoryLimit int64) {
	gcPercent, memoryLimit = KeepDefault, KeepDefault
	if goos == "android" || goos == "ios" {
		gcPercent, memoryLimit = mobileGCPercent, mobileMemoryLimit
	}
	if raw := env("SKIPI_GOGC"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			gcPercent = parsed
		}
	}
	if raw := env("SKIPI_GOMEMLIMIT"); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			memoryLimit = parsed
		}
	}
	return gcPercent, memoryLimit
}

// Init applies the runtime profile of this platform (see ResolveProfile) and GOMAXPROCS before
// any core starts.
func Init() {
	gcPercent, memoryLimit := ResolveProfile(runtime.GOOS, os.Getenv)
	if gcPercent != KeepDefault {
		debug.SetGCPercent(gcPercent)
	}
	if memoryLimit != KeepDefault {
		debug.SetMemoryLimit(memoryLimit)
	}
	ApplyMaxProcs()
}
