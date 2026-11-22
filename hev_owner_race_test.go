// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type observedStopHev struct {
	*fakeHev
	returned chan struct{}
}

func (h *observedStopHev) Stop() error { defer close(h.returned); return h.fakeHev.Stop() }

func TestTimedOutHevStopRejectsNewStartUntilItReturns(t *testing.T) {
	hev := &observedStopHev{fakeHev: &fakeHev{log: &callLog{}, stopEntered: make(chan struct{}, 1), stopRelease: make(chan struct{})}, returned: make(chan struct{})}
	hev.running.Store(true)
	previous := hevTun
	hevTun = hev
	oldOwner := NewCoreController(nil)
	claimHev(oldOwner, 1)
	defer func() { close(hev.stopRelease); <-hev.returned; hevTun = previous; releaseHevOwner() }()
	if err := stopHevIfOwned(oldOwner, 1, 20*time.Millisecond); !errors.Is(err, ErrStopTimedOut) {
		t.Fatalf("stop = %v, want timeout", err)
	}
	newOwner := NewCoreController(nil)
	newOwner.state, newOwner.gen = stateStarting, 1
	h := newOwner.beginSessionHev(1, &sessionPlanHev{ConfigYAML: "test", TunFd: 42})
	select {
	case <-h.done:
	case <-time.After(time.Second):
		t.Fatal("new start waited for the stuck HEV stop")
	}
	awaited := make(chan error, 1)
	go func() { awaited <- h.await() }()
	select {
	case err := <-awaited:
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "busy") {
			t.Fatalf("start = %v, want busy error while old stop runs", err)
		}
	case <-time.After(time.Second):
		t.Fatal("new start cleanup waited for the stuck HEV stop")
	}
	if hev.log.count("hev.start") != 0 {
		t.Fatal("new HEV started before the old stop returned")
	}
}

func TestForceStopOldStartLeavesNewHevOwnerRunning(t *testing.T) {
	hev := &fakeHev{log: &callLog{}}
	hev.running.Store(true)
	previous := hevTun
	hevTun = hev
	t.Cleanup(func() { hevTun = previous; releaseHevOwner() })
	c, next := NewCoreController(nil), NewCoreController(nil)
	c.SetStateListener(&recordingListener{})
	c.state, c.gen = stateStarting, 1
	claimHev(c, 1)
	beforeDeliver := func(state int) {
		if state == SessionIdle {
			claimHev(next, 1)
		}
	}
	testHookBeforeDeliver.Store(&beforeDeliver)
	defer testHookBeforeDeliver.Store(nil)
	_ = c.ForceStop()
	c.reapAbandonedStart(1)
	if !hev.Running() {
		t.Fatal("force stop of old start stopped the new owner's HEV")
	}
}

func TestSupersededStartCannotClaimNewOwnersHev(t *testing.T) {
	hev := &fakeHev{log: &callLog{}}
	hev.running.Store(true)
	previous := hevTun
	hevTun = hev
	t.Cleanup(func() { hevTun = previous; releaseHevOwner() })
	c := NewCoreController(nil)
	c.state, c.gen = stateStarting, 2
	claimHev(c, 2)
	h := c.beginSessionHev(1, &sessionPlanHev{ConfigYAML: "test", TunFd: 42})
	<-h.done
	if !errors.Is(h.err, errStartAborted) {
		t.Fatalf("old start = %v, want aborted", h.err)
	}
	hevOwner.Lock()
	owner, gen := hevOwner.c, hevOwner.gen
	hevOwner.Unlock()
	if owner != c || gen != 2 {
		t.Fatal("old start displaced the new HEV owner")
	}
}
