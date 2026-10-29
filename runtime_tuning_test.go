package skipicore

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
		if got := resolveMaxProcs(c.cpus, c.override); got != c.want {
			t.Errorf("resolveMaxProcs(%d, %q) = %d, want %d", c.cpus, c.override, got, c.want)
		}
	}
}

func TestPauseGCForStartupRestoresThePreviousPercent(t *testing.T) {
	original := debug.SetGCPercent(50)
	defer debug.SetGCPercent(original)

	restore := pauseGCForStartup()
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

	first := pauseGCForStartup()
	second := pauseGCForStartup()
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
