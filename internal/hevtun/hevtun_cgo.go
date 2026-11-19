// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build cgo && (android || (linux && skipi_hev))

package hevtun

/*
#cgo CFLAGS: -O2 -I${SRCDIR}/../../build/hev/include
#cgo android,arm64 LDFLAGS: -L${SRCDIR}/../../build/hev/android/arm64-v8a -lhev-socks5-tunnel -lyaml -llwip -lhev-task-system
#cgo android,arm LDFLAGS: -L${SRCDIR}/../../build/hev/android/armeabi-v7a -lhev-socks5-tunnel -lyaml -llwip -lhev-task-system
#cgo android,386 LDFLAGS: -L${SRCDIR}/../../build/hev/android/x86 -lhev-socks5-tunnel -lyaml -llwip -lhev-task-system
#cgo android,amd64 LDFLAGS: -L${SRCDIR}/../../build/hev/android/x86_64 -lhev-socks5-tunnel -lyaml -llwip -lhev-task-system
#cgo linux,!android,amd64 LDFLAGS: -L${SRCDIR}/../../build/hev/linux-amd64 -lhev-socks5-tunnel -lyaml -llwip -lhev-task-system -lpthread -lm

#include <stdlib.h>
#include "hev-main.h"
#include "hevtun_cgo.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// earlyExitWindow is how long Start watches for the hev main returning at once (a config that
// does not parse, a bad TUN descriptor) so that failure is reported by Start itself.
const earlyExitWindow = 50 * time.Millisecond

type instance struct {
	done chan struct{} // closed when the hev main returned
	res  int
}

var (
	mu     sync.Mutex
	active *instance
)

// current returns the instance whose main has not returned yet, or nil.
func current() *instance {
	mu.Lock()
	defer mu.Unlock()
	if active != nil {
		select {
		case <-active.done:
			active = nil
		default:
		}
	}
	return active
}

// NeedsTunFd reports that this target runs hev in process on a TUN descriptor the caller opened.
func NeedsTunFd() bool { return true }

// Start runs hev on a dedicated, locked OS thread with the given YAML config and TUN
// descriptor. executable is only used by the Windows process mode and ignored here. It does not wait for readiness (see WaitReady) but fails at once when the hev
// main returns right away. Only one instance can run per process.
func Start(configYAML string, opts Options) error {
	tunFd := opts.TunFd
	if configYAML == "" {
		return errors.New("HEV TUN config is empty")
	}
	if tunFd <= 0 {
		return fmt.Errorf("HEV TUN needs a TUN descriptor, got %d", tunFd)
	}
	mu.Lock()
	if active != nil {
		select {
		case <-active.done:
			active = nil
		default:
			mu.Unlock()
			return errors.New("HEV TUN is already running")
		}
	}
	inst := &instance{done: make(chan struct{})}
	active = inst
	mu.Unlock()

	C.skipi_hev_reset()
	cfg := C.CBytes([]byte(configYAML))
	cfgLen := C.uint(len(configYAML))
	go func() {
		// hev drives its own coroutine scheduler on this thread until quit.
		runtime.LockOSThread()
		inst.res = int(C.skipi_hev_run((*C.uchar)(cfg), cfgLen, C.int(tunFd)))
		C.free(cfg)
		close(inst.done)
	}()

	select {
	case <-inst.done:
		return fmt.Errorf("HEV TUN main returned immediately (code %d); see the hev log", inst.res)
	case <-time.After(earlyExitWindow):
		return nil
	}
}

// WaitReady blocks until hev reports the tunnel initialized. It returns ErrReadyTimeout when
// the timeout passes first and ErrExited when the hev main returned.
func WaitReady(timeout time.Duration) error {
	inst := current()
	if inst == nil {
		return errors.New("HEV TUN is not running")
	}
	ms := timeout.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	if ms > 1<<30 {
		ms = 1 << 30
	}
	switch C.skipi_hev_wait_ready(C.int(ms)) {
	case 1:
		return nil
	case -1:
		return fmt.Errorf("%w (code %d)", ErrExited, inst.res)
	}
	return ErrReadyTimeout
}

// Stop asks hev to quit and waits until its main returned. It blocks as long as hev takes;
// callers bound it. Stopping a tunnel that is not running is a no-op.
func Stop() error {
	inst := current()
	if inst == nil {
		return nil
	}
	C.hev_socks5_tunnel_quit()
	<-inst.done
	mu.Lock()
	if active == inst {
		active = nil
	}
	mu.Unlock()
	return nil
}

// Stats returns the tunnel interface counters; zeros when hev is not running.
func Stats() (txPackets, txBytes, rxPackets, rxBytes uint64) {
	if current() == nil {
		return 0, 0, 0, 0
	}
	var a, b, c, d C.size_t
	C.hev_socks5_tunnel_stats(&a, &b, &c, &d)
	return uint64(a), uint64(b), uint64(c), uint64(d)
}

// Running reports whether the hev main is running.
func Running() bool { return current() != nil }
