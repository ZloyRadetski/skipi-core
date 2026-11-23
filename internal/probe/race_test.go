// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package probe

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// The instance the probes dial through is closed after raceCandidates returns, so no probe may
// still be running by then, even when the winner was picked early.
func TestRaceCandidatesWaitsForEveryProbeBeforeReturning(t *testing.T) {
	var running atomic.Int32
	probeFn := func(ctx context.Context, tag string) (int64, error) {
		running.Add(1)
		defer running.Add(-1)
		if tag == "fast" {
			return 10, nil
		}
		<-ctx.Done()
		time.Sleep(50 * time.Millisecond)
		return -1, errors.New("cancelled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := raceCandidates(ctx, cancel, []string{"fast", "slow1", "slow2"}, probeFn)
	if got != "fast" {
		t.Fatalf("winner = %q", got)
	}
	if n := running.Load(); n != 0 {
		t.Fatalf("%d probes still running after the race returned", n)
	}
}

func TestRaceCandidatesFallsBackToTheFirstWhenNothingAnswers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got := raceCandidates(ctx, cancel, []string{"a", "b"}, func(context.Context, string) (int64, error) { return -1, errors.New("dead") })
	if got != "a" {
		t.Fatalf("got %q", got)
	}
}
