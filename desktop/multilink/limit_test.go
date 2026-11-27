// Based on net-merge (https://github.com/net-merge/net-merge), Copyright (c) 2026 Rohit Mahto, MIT License;
// see third_party/net-merge. Changes for SKIPI Core: Copyright 2026, Radetski, GPL-3.0.

package multilink

import (
	"io"
	"testing"
	"time"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink/nics"
)

func TestParseLimit(t *testing.T) {
	for _, c := range []struct {
		in   string
		want float64
		ok   bool
	}{
		{"10", 10, true},
		{" 7.5 ", 7.5, true},
		{"0", 0, true},
		{"unlimited", 0, true},
		{"Off", 0, true},
		{"none", 0, true},
		{"", 0, false},
		{"fast", 0, false},
		{"-1", 0, false},
		{"NaN", 0, false},
		{"+Inf", 0, false},
		{"1e7", 0, false}, // over LimitMaxMbps
	} {
		got, err := ParseLimit(c.in)
		if c.ok && err != nil {
			t.Errorf("ParseLimit(%q): %v", c.in, err)
		}
		if !c.ok && err == nil {
			t.Errorf("ParseLimit(%q) = %v, want an error", c.in, got)
		}
		if c.ok && got != c.want {
			t.Errorf("ParseLimit(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestBucketPacesAfterTheBurst(t *testing.T) {
	b := newBucket(100_000) // 100 KB/s, below the minimum burst
	start := time.Now()
	b.take(limitBurstMin, nil) // a quiet bucket starts full, so the first chunk is free
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("the initial burst waited %s", d)
	}
	start = time.Now()
	b.take(limitChunkMin, nil)
	if d := time.Since(start); d < 100*time.Millisecond {
		t.Fatalf("16 KB at 100 KB/s took %s, want about 164 ms", d)
	}
}

func TestThrottleWithoutLimitIsFree(t *testing.T) {
	sl := &Slot{}
	start := time.Now()
	for i := 0; i < 100; i++ {
		sl.throttle(true, 64<<10, nil)
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("throttling an unlimited adapter took %s", d)
	}
}

func TestThrottleKeepsDirectionsSeparate(t *testing.T) {
	sl := &Slot{}
	sl.setLimit(4) // 4 Mbit/s = 500 KB/s
	sl.throttle(false, 64<<10, nil)
	start := time.Now()
	sl.throttle(true, limitChunkMin, nil) // the download bucket is untouched
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("download waited %s behind upload traffic", d)
	}
}

func TestLimitUnits(t *testing.T) {
	sl := &Slot{}
	sl.setLimit(400) // 400 Mbit/s = 50 MB/s
	p := sl.limit.Load()
	if p == nil {
		t.Fatal("no cap installed")
	}
	const wantRate = 400 * bytesPerMbit
	if p.in.rate != wantRate || p.out.rate != wantRate {
		t.Fatalf("rate = %v/%v B/s, want %v", p.in.rate, p.out.rate, float64(wantRate))
	}
	if p.chunk != 250_000 {
		t.Fatalf("chunk = %d, want 250000 (rate x 5 ms)", p.chunk)
	}
	if p.in.burst != 2_500_000 {
		t.Fatalf("burst = %v, want 2500000 (rate x 50 ms)", p.in.burst)
	}
	if got := sl.limitMbps(); got != 400 {
		t.Fatalf("limitMbps = %v, want 400", got)
	}

	sl.setLimit(1) // 125 KB/s: the minimum chunk and burst apply
	p = sl.limit.Load()
	if p.chunk != limitChunkMin || p.in.burst != limitBurstMin {
		t.Fatalf("chunk/burst = %d/%v at 1 Mbit/s, want %d/%d", p.chunk, p.in.burst, limitChunkMin, limitBurstMin)
	}

	sl.setLimit(0)
	if sl.limit.Load() != nil || sl.limitMbps() != 0 {
		t.Fatal("0 did not clear the cap")
	}
}

func TestHighCapIsReached(t *testing.T) {
	sl := &Slot{}
	sl.setLimit(400) // 50 MB/s
	const size = 8 << 20
	start := time.Now()
	if _, err := sl.writePaced(io.Discard, make([]byte, size), false, nil); err != nil {
		t.Fatal(err)
	}
	d := time.Since(start)
	// 8 MB at 50 MB/s is 160 ms; the first 2.5 MB (50 ms worth) passes as burst, so ~110 ms is right.
	// 16 KB chunks would spend most of their time in timer overshoot and land far below the cap.
	if d < 70*time.Millisecond {
		t.Fatalf("8 MB at 400 Mbit/s took only %s: the cap was not applied", d)
	}
	if d > 400*time.Millisecond {
		t.Fatalf("8 MB at 400 Mbit/s took %s, want about 110-200 ms", d)
	}
}

func TestLimitsFollowAdapters(t *testing.T) {
	s := NewScheduler([]nics.Nic{nic("A", "10.0.0.1", 1)})
	s.SetLimit("A", 5)
	s.SetLimit("B", 10) // not seen yet: saved for when it appears

	limitOf := func(name string) float64 {
		for _, st := range s.Snapshot() {
			if st.Name == name {
				return st.LimitMbps
			}
		}
		t.Fatalf("adapter %q not in the snapshot", name)
		return 0
	}
	if got := limitOf("A"); got != 5 {
		t.Fatalf("A has limit %v, want 5", got)
	}

	s.Update([]nics.Nic{nic("A", "10.0.0.1", 1), nic("B", "10.0.0.2", 1)})
	if got := limitOf("B"); got != 10 {
		t.Fatalf("B came back with limit %v, want 10", got)
	}
	if limits := s.Limits(); len(limits) != 2 || limits["A"] != 5 || limits["B"] != 10 {
		t.Fatalf("Limits() = %v, want A=5 B=10", limits)
	}

	s.SetLimits(map[string]float64{"C": 20})
	if got := limitOf("A"); got != 0 {
		t.Fatalf("A still has limit %v after SetLimits replaced the map", got)
	}
	if limits := s.Limits(); len(limits) != 1 || limits["C"] != 20 {
		t.Fatalf("Limits() = %v, want only C=20", limits)
	}
	s.SetLimit("C", 0)
	if limits := s.Limits(); len(limits) != 0 {
		t.Fatalf("Limits() = %v after clearing C, want empty", limits)
	}
}
