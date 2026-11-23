// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/xtls/xray-core/core"
)

func stubTunFd(t *testing.T, dup func(int64) (int64, error), closeFd func(int64)) {
	t.Helper()
	origDup, origClose := dupTunFd, closeTunFd
	dupTunFd, closeTunFd = dup, closeFd
	t.Cleanup(func() { dupTunFd, closeTunFd = origDup, origClose })
}

// Xray's Linux TUN takes ownership of the descriptor it finds in the environment and closes it on
// stop, so Core must publish a duplicate and leave the caller's descriptor to the caller.
func TestStartLoopPublishesDuplicateOfTunFd(t *testing.T) {
	clearTunFdEnv()
	stubTunFd(t, func(fd int64) (int64, error) { return fd + 1000, nil }, func(int64) { t.Error("close must not run on success") })

	ctrl := NewCoreController(&dummyCallbackHandler{})
	if err := ctrl.StartLoop(`{"log":{"loglevel":"none"},"outbounds":[{"protocol":"freedom","tag":"direct"}]}`, 42); err != nil {
		t.Fatalf("StartLoop: %v", err)
	}
	defer ctrl.StopLoop()
	if got := os.Getenv(tunFdKey); got != strconv.Itoa(1042) {
		t.Fatalf("expected the duplicate to be published, got %q", got)
	}
}

// When Xray never took the duplicate (core.New failed), Core closes it.
func TestStartLoopClosesDuplicateWhenInstanceCreationFails(t *testing.T) {
	clearTunFdEnv()
	var closed []int64
	stubTunFd(t, func(fd int64) (int64, error) { return 900, nil }, func(fd int64) { closed = append(closed, fd) })
	orig := createCoreInstance
	createCoreInstance = func(*core.Config) (coreInstance, error) { return nil, errors.New("boom") }
	t.Cleanup(func() { createCoreInstance = orig })

	ctrl := NewCoreController(&dummyCallbackHandler{})
	if err := ctrl.StartLoop(`{"log":{"loglevel":"none"},"outbounds":[{"protocol":"freedom","tag":"direct"}]}`, 42); err == nil {
		t.Fatal("expected failure")
	}
	if len(closed) != 1 || closed[0] != 900 {
		t.Fatalf("expected the duplicate 900 to be closed once, got %v", closed)
	}
}

func TestStartLoopFailsWhenTunFdCannotBeDuplicated(t *testing.T) {
	clearTunFdEnv()
	stubTunFd(t, func(int64) (int64, error) { return 0, errors.New("EBADF") }, func(int64) {})
	ctrl := NewCoreController(&dummyCallbackHandler{})
	if err := ctrl.StartLoop(`{"log":{"loglevel":"none"},"outbounds":[{"protocol":"freedom","tag":"direct"}]}`, 42); err == nil {
		t.Fatal("expected failure")
	}
	if ctrl.IsRunning() || os.Getenv(tunFdKey) != "" {
		t.Fatal("failed start must leave nothing behind")
	}
}
