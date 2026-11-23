// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package netbind

import (
	"errors"
	"testing"
)

// A dual-stack socket accepts both options; skipping the IPv6 one after the IPv4 one succeeded
// would leave its IPv6 traffic unbound.
func TestApplyUnicastIfSetsBothFamilies(t *testing.T) {
	var levels []int
	err := applyUnicastIf(func(level, value int) error {
		levels = append(levels, level)
		return nil
	}, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(levels) != 2 || levels[0] != ipprotoIP || levels[1] != ipprotoIPv6 {
		t.Fatalf("levels = %v", levels)
	}
}

func TestApplyUnicastIfSucceedsWhenOneFamilyIsAccepted(t *testing.T) {
	err := applyUnicastIf(func(level, value int) error {
		if level == ipprotoIP {
			return errors.New("not an IPv4 socket")
		}
		return nil
	}, 7)
	if err != nil {
		t.Fatal(err)
	}
}

func TestApplyUnicastIfFailsWhenBothAreRefused(t *testing.T) {
	if err := applyUnicastIf(func(int, int) error { return errors.New("no") }, 7); err == nil {
		t.Fatal("expected an error")
	}
}
