package runtimetuning

import (
	"runtime/debug"
	"testing"
)

func TestResolveMaxProcs(t *testing.T) {
	cases := []struct {
		cpus     int
		override string
		want     int
	}{
		{8, "", 4},
		{6, "", 3},
		{4, "", 2},
		{2, "", 2},
		{1, "", 1},
		{8, "3", 3},
		{8, "99", 8},
		{8, "abc", 4},
		{8, "0", 4},
		{8, "-2", 4},
	}
	for _, c := range cases {
		if got := ResolveMaxProcs(c.cpus, c.override); got != c.want {
			t.Errorf("ResolveMaxProcs(%d, %q) = %d, want %d", c.cpus, c.override, got, c.want)
		}
	}
}

func TestPauseGCForStartupRestoresThePreviousPercent(t *testing.T) {
	original := debug.SetGCPercent(50)
	defer debug.SetGCPercent(original)

	restore := PauseGCForStartup()
	if got := debug.SetGCPercent(-1); got != -1 {
		t.Fatalf("GC percent while paused = %d, want -1 (disabled)", got)
	}
	restore()
	if got := debug.SetGCPercent(50); got != 50 {
		t.Fatalf("GC percent after restore = %d, want 50", got)
	}
}

func TestPauseGCForStartupNestsAndRestoreIsIdempotent(t *testing.T) {
	original := debug.SetGCPercent(50)
	defer debug.SetGCPercent(original)

	first := PauseGCForStartup()
	second := PauseGCForStartup()
	first()
	first() // a repeated restore must not release the other holder
	if got := debug.SetGCPercent(-1); got != -1 {
		t.Fatalf("GC resumed while a start was still running: percent = %d", got)
	}
	second()
	if got := debug.SetGCPercent(50); got != 50 {
		t.Fatalf("GC percent after the last restore = %d, want 50", got)
	}
}

// Perf 4: GOGC 50 and the 256 MiB soft limit are a mobile profile. On a desktop a big heap is
// normal, and the limit there means a collection all the time; it keeps the Go defaults.
func TestTheMobileProfileStaysOnMobile(t *testing.T) {
	none := func(string) string { return "" }
	for _, goos := range []string{"android", "ios"} {
		gc, limit := ResolveProfile(goos, none)
		if gc != 50 || limit != 256<<20 {
			t.Errorf("%s: gc=%d limit=%d", goos, gc, limit)
		}
	}
	for _, goos := range []string{"windows", "linux", "darwin"} {
		gc, limit := ResolveProfile(goos, none)
		if gc != KeepDefault || limit != KeepDefault {
			t.Errorf("%s: gc=%d limit=%d, want the Go defaults", goos, gc, limit)
		}
	}
	env := func(k string) string {
		return map[string]string{"SKIPI_GOGC": "80", "SKIPI_GOMEMLIMIT": "1073741824"}[k]
	}
	if gc, limit := ResolveProfile("windows", env); gc != 80 || limit != 1<<30 {
		t.Errorf("overrides apply everywhere: gc=%d limit=%d", gc, limit)
	}
}
