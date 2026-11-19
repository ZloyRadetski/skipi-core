package memstats

import "testing"

// The lock-free metrics path must stay usable: with a wrong metric name or kind it silently
// returned nil and every call fell back to the stop-the-world MemStats read.
func TestReadMemoryStatsUsesMetricsPath(t *testing.T) {
	stats := ReadFromMetrics()
	if stats == nil {
		t.Fatal("runtime/metrics path unavailable")
	}
	if stats.AllocBytes <= 0 || stats.SysBytes <= 0 || stats.NumGoroutines <= 0 || stats.NumGC == 0 && stats.TotalAlloc <= 0 {
		t.Fatalf("implausible stats: %+v", stats)
	}
}
