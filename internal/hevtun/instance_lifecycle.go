// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hevtun

import (
	"errors"
	"sync"
)

type instance struct {
	done  chan struct{}
	ready chan struct{}
	res   int
}

func (i *instance) waitUntilQuitReady() bool {
	select {
	case <-i.done:
		return false
	case <-i.ready:
		select {
		case <-i.done:
			return false
		default:
			return true
		}
	}
}

type instanceLifecycle struct {
	mu            sync.Mutex
	active        *instance
	quitting      bool
	quitRequested bool
}

func (l *instanceLifecycle) currentLocked() *instance {
	if l.active != nil {
		select {
		case <-l.active.done:
			l.active = nil
		default:
		}
	}
	return l.active
}

func (l *instanceLifecycle) current() *instance {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.currentLocked()
}

func (l *instanceLifecycle) latest() *instance {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active
}

func (l *instanceLifecycle) start() (*instance, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.quitting {
		return nil, errors.New("HEV TUN is still stopping")
	}
	if l.currentLocked() != nil {
		return nil, errors.New("HEV TUN is already running")
	}
	l.active = &instance{done: make(chan struct{}), ready: make(chan struct{})}
	l.quitRequested = false
	return l.active, nil
}

func (l *instanceLifecycle) beginStop() (*instance, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	inst := l.currentLocked()
	if inst == nil {
		return nil, false
	}
	if l.quitRequested {
		return inst, false
	}
	l.quitting = true
	l.quitRequested = true
	return inst, true
}

func (l *instanceLifecycle) endQuit() {
	l.mu.Lock()
	l.quitting = false
	l.mu.Unlock()
}
