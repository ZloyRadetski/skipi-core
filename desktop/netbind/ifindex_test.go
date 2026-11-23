// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package netbind

import (
	"errors"
	"testing"
	"time"
)

func TestIfIndexCacheResolvesOncePerTTL(t *testing.T) {
	now := time.Unix(100, 0)
	calls := 0
	c := newIfIndexCache(func(name string) (int, error) { calls++; return 9, nil }, time.Minute, func() time.Time { return now })
	for i := 0; i < 5; i++ {
		if got, err := c.index("en0"); err != nil || got != 9 {
			t.Fatalf("index = %d, %v", got, err)
		}
	}
	if calls != 1 {
		t.Fatalf("resolved %d times, want 1", calls)
	}
	now = now.Add(2 * time.Minute)
	_, _ = c.index("en0")
	if calls != 2 {
		t.Fatalf("expired entry was not resolved again: %d", calls)
	}
}

func TestIfIndexCacheDoesNotCacheFailures(t *testing.T) {
	calls := 0
	c := newIfIndexCache(func(string) (int, error) { calls++; return 0, errors.New("gone") }, time.Minute, time.Now)
	_, _ = c.index("en0")
	_, _ = c.index("en0")
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
}
