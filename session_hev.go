// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ZloyRadetski/skipi-core/internal/hevtun"
	"github.com/ZloyRadetski/skipi-core/internal/lifecycle"
)

// hevTunnel is the HEV TUN the session drives. The production value forwards to internal/hevtun
// (cgo on Android and Linux, a supervised process on Windows, a stub elsewhere); tests substitute a fake.
type hevTunnel interface {
	// NeedsTunFd reports whether this target runs hev in process on a descriptor the host opened
	// (Android, Linux). A process-mode target (Windows) creates the interface itself.
	NeedsTunFd() bool
	// NeedsMacInterface reports whether this target (macOS) takes the interface plan, the run
	// directory and the hev executable in the plan instead of a descriptor.
	NeedsMacInterface() bool
	// ReadyTimeout is the readiness wait this target needs when it is longer than hevReadyTimeout.
	ReadyTimeout() time.Duration
	Start(configYAML string, opts hevtun.Options) error
	WaitReady(timeout time.Duration) error
	Stop() error
	Stats() (txPackets, txBytes, rxPackets, rxBytes uint64)
	Running() bool
	// Exited is closed when the running hev ends, or nil when this target cannot tell (macOS,
	// whose hev lives in a root process); the session then polls Running.
	Exited() <-chan struct{}
}

type realHevTunnel struct{}

func (realHevTunnel) NeedsTunFd() bool            { return hevtun.NeedsTunFd() }
func (realHevTunnel) NeedsMacInterface() bool     { return hevtun.NeedsMacInterface() }
func (realHevTunnel) ReadyTimeout() time.Duration { return hevtun.ReadyTimeout() }
func (realHevTunnel) Start(configYAML string, opts hevtun.Options) error {
	return hevtun.Start(configYAML, opts)
}
func (realHevTunnel) WaitReady(timeout time.Duration) error   { return hevtun.WaitReady(timeout) }
func (realHevTunnel) Stop() error                             { return hevtun.Stop() }
func (realHevTunnel) Stats() (uint64, uint64, uint64, uint64) { return hevtun.Stats() }
func (realHevTunnel) Running() bool                           { return hevtun.Running() }
func (realHevTunnel) Exited() <-chan struct{}                 { return hevtun.Exited() }

// Seams for the HEV TUN part of a session.
var (
	hevTun hevTunnel = realHevTunnel{}
	// hevReadyTimeout is how long StartSession waits for HEV TUN to report readiness.
	hevReadyTimeout = 5000 * time.Millisecond
)

// hevWatchInterval is how often a running session checks that HEV TUN is still alive.
var hevWatchInterval = time.Second

// hevExitedReason leads the Idle detail when the session stopped because HEV TUN exited.
const hevExitedReason = "HEV TUN exited unexpectedly"

// watchHev stops session gen when HEV TUN exits under it: without hev the TUN drops every packet
// while Xray and the session still look healthy. It returns once that session is no longer running.
func (c *CoreController) watchHev(gen uint64) {
	stillCurrent := func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.gen == gen && c.state == stateRunning && c.ownsHev
	}
	exitedUnder := func() {
		log.Printf("SKIPI Core: %s; stopping the session", hevExitedReason)
		_ = c.stopWithinReason(defaultStopTimeout, hevExitedReason)
	}
	// Where the target reports the exit, wait for it: no wake-ups, and the stop follows at once.
	// A normal stop ends hev too, and the check below then finds the session no longer current.
	if exited := hevTun.Exited(); exited != nil {
		<-exited
		if stillCurrent() {
			exitedUnder()
		}
		return
	}
	ticker := time.NewTicker(hevWatchInterval)
	defer ticker.Stop()
	for range ticker.C {
		if !stillCurrent() {
			return
		}
		if hevTun.Running() {
			continue
		}
		exitedUnder()
		return
	}
}

// hevReadyPoll is the slice StartSession waits in, so a ForceStop ends the wait promptly.
const hevReadyPoll = 100 * time.Millisecond

type sessionPlanHev struct {
	ConfigYAML string `json:"configYaml"`
	TunFd      int    `json:"tunFd"`
	// Executable is the hev executable of the process modes (Windows, macOS); ignored by in-process targets.
	Executable string `json:"executable"`
	// RunDirectory is where the macOS supervisor keeps its marker files and the hev config.
	RunDirectory string `json:"runDirectory"`
	// MacInterface is the macOS utun plan (name, mtu, addresses, routes, dns).
	MacInterface *hevtun.MacInterface `json:"macInterface"`
}

// hevOwner is the start attempt (controller and generation) that started the HEV TUN now running.
// HEV TUN is a process singleton: a start that ForceStop aborted cleans up after itself late,
// and by then a newer session may run its own hev, which that cleanup must leave alone.
var hevOwner struct {
	sync.Mutex
	c   *CoreController
	gen uint64
}

func claimHev(c *CoreController, gen uint64) {
	hevOwner.Lock()
	hevOwner.c, hevOwner.gen = c, gen
	hevOwner.Unlock()
}

// releaseHevOwner forgets the owner after a stop that stopped HEV TUN whoever started it.
func releaseHevOwner() {
	hevOwner.Lock()
	hevOwner.c, hevOwner.gen = nil, 0
	hevOwner.Unlock()
}

// stopHevIfOwned stops HEV TUN only while start attempt gen of c still owns it.
func stopHevIfOwned(c *CoreController, gen uint64, d time.Duration) error {
	hevOwner.Lock()
	owned := hevOwner.c == c && hevOwner.gen == gen
	hevOwner.Unlock()
	if !owned {
		return nil
	}
	err := stopHevBounded(d, nil)
	hevOwner.Lock()
	if hevOwner.c == c && hevOwner.gen == gen {
		hevOwner.c, hevOwner.gen = nil, 0
	}
	hevOwner.Unlock()
	return err
}

// stopHevBounded stops HEV TUN within d; a stop that hangs is counted in AbandonedInstances
// until it returns and reported as ErrStopTimedOut. cancel, when set, also ends the wait.
func stopHevBounded(d time.Duration, cancel <-chan struct{}) error {
	err, timedOut := lifecycle.RunBounded(hevTun.Stop, d, cancel)
	if timedOut {
		return fmt.Errorf("%w: HEV TUN did not stop within %v", ErrStopTimedOut, d)
	}
	if err != nil {
		return fmt.Errorf("HEV TUN stop: %w", err)
	}
	return nil
}

// startSessionHev starts HEV TUN and waits for it to be ready. On any failure it stops it again
// before returning. gen is the start attempt; a ForceStop that supersedes it ends the wait.
func (c *CoreController) startSessionHev(gen uint64, cfg *sessionPlanHev) error {
	if c.superseded(gen) {
		return errStartAborted
	}
	opts := hevtun.Options{TunFd: cfg.TunFd, Executable: cfg.Executable, RunDirectory: cfg.RunDirectory, MacInterface: cfg.MacInterface}
	claimHev(c, gen)
	if err := hevTun.Start(cfg.ConfigYAML, opts); err != nil {
		_ = stopHevIfOwned(c, gen, defaultStopTimeout)
		return fmt.Errorf("HEV TUN failed to start: %w", err)
	}
	readyTimeout := max(hevReadyTimeout, hevTun.ReadyTimeout())
	deadline := time.Now().Add(readyTimeout)
	for {
		if c.superseded(gen) {
			_ = stopHevIfOwned(c, gen, defaultStopTimeout)
			return errStartAborted
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			_ = stopHevIfOwned(c, gen, defaultStopTimeout)
			return fmt.Errorf("HEV TUN was not ready: timed out after %v", readyTimeout)
		}
		err := hevTun.WaitReady(min(remaining, hevReadyPoll))
		if err == nil {
			return nil
		}
		if errors.Is(err, hevtun.ErrReadyTimeout) {
			continue
		}
		_ = stopHevIfOwned(c, gen, defaultStopTimeout)
		return fmt.Errorf("HEV TUN was not ready: %w", err)
	}
}

// QueryTunnelStats returns the HEV TUN interface counters as JSON:
// {"txPackets":N,"txBytes":N,"rxPackets":N,"rxBytes":N}. All zeros when HEV TUN is not running.
func (c *CoreController) QueryTunnelStats() string {
	var s struct {
		TxPackets uint64 `json:"txPackets"`
		TxBytes   uint64 `json:"txBytes"`
		RxPackets uint64 `json:"rxPackets"`
		RxBytes   uint64 `json:"rxBytes"`
	}
	if hevTun.Running() {
		s.TxPackets, s.TxBytes, s.RxPackets, s.RxBytes = hevTun.Stats()
	}
	out, _ := json.Marshal(s)
	return string(out)
}
