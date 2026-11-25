package memstats

import (
	"encoding/json"
	"testing"
)

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

func TestExternalBytesComeFromTheRegisteredProvider(t *testing.T) {
	defer SetExternalBytes(nil)
	SetExternalBytes(func() int64 { return 12_345_678 })

	for name, stats := range map[string]*Stats{"metrics": ReadFromMetrics(), "memstats": ReadFromMemStats()} {
		if stats == nil {
			t.Fatalf("%s: no stats", name)
		}
		if stats.ExternalBytes != 12_345_678 {
			t.Fatalf("%s: ExternalBytes = %d, want 12345678", name, stats.ExternalBytes)
		}
	}
	var decoded struct {
		ExternalBytes int64 `json:"externalBytes"`
	}
	if err := json.Unmarshal([]byte(JSON()), &decoded); err != nil || decoded.ExternalBytes != 12_345_678 {
		t.Fatalf("JSON externalBytes = %d (%v), want 12345678", decoded.ExternalBytes, err)
	}
}

func TestExternalBytesAreZeroWithoutAProviderOrWithANegativeOne(t *testing.T) {
	SetExternalBytes(nil)
	if got := ReadFromMetrics().ExternalBytes; got != 0 {
		t.Fatalf("no provider: ExternalBytes = %d, want 0", got)
	}
	defer SetExternalBytes(nil)
	SetExternalBytes(func() int64 { return -5 })
	if got := ReadFromMetrics().ExternalBytes; got != 0 {
		t.Fatalf("negative provider: ExternalBytes = %d, want 0", got)
	}
}

// HeapInuse is MemStats.HeapInuse: the spans in use, so live objects plus the unused part of
// those spans, never less than the live objects. Both read paths must agree on that meaning.
func TestHeapInuseCountsSpanSlackAboveLiveObjects(t *testing.T) {
	keep := make([][]byte, 0, 20000)
	for i := 0; i < 20000; i++ {
		keep = append(keep, make([]byte, 33)) // an awkward size class leaves slack in every span
	}
	defer func() { _ = keep }()
	m := ReadFromMetrics()
	if m.HeapInuse <= m.AllocBytes {
		t.Fatalf("metrics HeapInuse = %d, AllocBytes = %d: HeapInuse must include span slack", m.HeapInuse, m.AllocBytes)
	}
}
