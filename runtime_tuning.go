package skipicore

import (
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
)

// resolveMaxProcs picks how many OS threads may run Go code at once.
//
// The core shares a process (and the CPU's few big cores) with the UI. Letting Go use every
// core makes a tunnel start or a heavy download compete with the UI thread and shows up as
// dropped frames; proxy forwarding is I/O bound, so half the cores is plenty. The result is
// never below 2 (or the CPU count on a single-core device) and an explicit override in
// 1..numCPU wins.
func resolveMaxProcs(numCPU int, override string) int {
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

// pauseGCForStartup disables the periodic GC for the duration of a core start. Parsing the
// routing rules and geo data allocates a large burst of long-lived memory; with the low GOGC
// used for steady state the collector would rescan that growing heap again and again on every
// core while the UI is trying to animate. The soft memory limit stays active as the safety
// net. The returned function is idempotent; the previous percentage returns once the last
// concurrent holder has restored.
func pauseGCForStartup() func() {
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

func applyMaxProcs() {
	runtime.GOMAXPROCS(resolveMaxProcs(runtime.NumCPU(), os.Getenv("SKIPI_GOMAXPROCS")))
}
