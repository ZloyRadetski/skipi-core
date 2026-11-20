package skipicore

import (
	"encoding/json"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryStats(t *testing.T) {
	ForceFreeMemory()

	statsJSON := ReadMemoryStats()
	if statsJSON == "" {
		t.Fatal("ReadMemoryStats returned empty string")
	}

	var stats MemoryStats
	if err := json.Unmarshal([]byte(statsJSON), &stats); err != nil {
		t.Fatalf("failed to unmarshal MemoryStats: %v", err)
	}

	if stats.AllocBytes <= 0 {
		t.Fatalf("expected positive AllocBytes, got: %d", stats.AllocBytes)
	}
	if stats.SysBytes <= 0 {
		t.Fatalf("expected positive SysBytes, got: %d", stats.SysBytes)
	}
	if stats.NumGoroutines <= 0 {
		t.Fatalf("expected positive NumGoroutines, got: %d", stats.NumGoroutines)
	}

	t.Logf("Memory stats: Alloc=%s, Sys=%s, Goroutines=%d, NumGC=%d",
		stats.AllocMb, stats.SysMb, stats.NumGoroutines, stats.NumGC)
}

// The UI polls memory stats periodically while the tunnel forwards traffic:
// the metrics-based read must stay allocation-free, unlike MemStats.
func BenchmarkReadMemoryStats(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ReadMemoryStats()
	}
}

// Reference point: the legacy stop-the-world read this benchmark contrasts
// against BenchmarkReadMemoryStats.
func BenchmarkLegacyReadMemStats(b *testing.B) {
	var m runtime.MemStats
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		runtime.ReadMemStats(&m)
	}
}

// Perf 5: a start leaves the parsed routing and geo data behind as garbage and a stop frees the
// whole instance; both hand the freed memory back to the OS in the background, so the resident
// size in the background (what Android's low-memory killer looks at) drops.
func TestStartAndStopReturnFreedMemoryToTheOS(t *testing.T) {
	var calls atomic.Int32
	orig := releaseMemoryFn.Load()
	count := func() { calls.Add(1) }
	releaseMemoryFn.Store(&count)
	defer releaseMemoryFn.Store(orig)

	installFakeCore(t, newFakeCoreInstance())
	c := NewCoreController(nil)
	if err := c.StartLoop(stopTestConfig, 0); err != nil {
		t.Fatal(err)
	}
	waitFor := func(n int32, what string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for calls.Load() < n {
			if time.Now().After(deadline) {
				t.Fatalf("memory was not released after the %s", what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitFor(1, "start")
	if err := c.StopLoop(); err != nil {
		t.Fatal(err)
	}
	waitFor(2, "stop")
}
