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
//
// The target and the poll interval are read by the caller, not here: this goroutine can outlive
// the session by a moment, and the package variables are swapped by tests (and by nothing else).
func (c *CoreController) watchHev(gen uint64, tun hevTunnel, interval time.Duration) {
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
	if exited := tun.Exited(); exited != nil {
		<-exited
		if stillCurrent() {
			exitedUnder()
		}
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if !stillCurrent() {
			return
		}
		if tun.Running() {
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

// Remains locked until the native stop actually returns, even after its caller times out.
var hevStopGate sync.Mutex

func claimHev(c *CoreController, gen uint64) bool {
	if !hevStopGate.TryLock() {
		return false
	}
	defer hevStopGate.Unlock()
	hevOwner.Lock()
	hevOwner.c, hevOwner.gen = c, gen
	hevOwner.Unlock()
	return true
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
	return stopHevGuarded(d, nil, hevTun, c, gen, false)
}

// stopHevUnlessOwnedByOther stops HEV TUN unless a different start attempt has claimed it since.
// It stops through tun, the target the start used, so a late goroutine never reads the package variable.
func stopHevUnlessOwnedByOther(c *CoreController, gen uint64, tun hevTunnel, d time.Duration) {
	_ = stopHevGuarded(d, nil, tun, c, gen, true)
}

// stopHevBounded stops HEV TUN within d; a stop that hangs is counted in AbandonedInstances
// until it returns and reported as ErrStopTimedOut. cancel, when set, also ends the wait.
func stopHevBounded(c *CoreController, gen uint64, d time.Duration, cancel <-chan struct{}) error {
	return stopHevGuarded(d, cancel, hevTun, c, gen, false)
}

func stopHevGuarded(d time.Duration, cancel <-chan struct{}, tun hevTunnel, c *CoreController, gen uint64, allowUnowned bool) error {
	err, timedOut := lifecycle.RunBounded(func() error {
		hevStopGate.Lock()
		defer hevStopGate.Unlock()
		hevOwner.Lock()
		owned := hevOwner.c == c && hevOwner.gen == gen
		if allowUnowned && hevOwner.c == nil {
			owned = true
		}
		hevOwner.Unlock()
		if !owned {
			return nil
		}
		err := tun.Stop()
		hevOwner.Lock()
		if hevOwner.c == c && hevOwner.gen == gen {
			hevOwner.c, hevOwner.gen = nil, 0
		}
		hevOwner.Unlock()
		return err
	}, d, cancel)
	if timedOut {
		return fmt.Errorf("%w: HEV TUN did not stop within %v", ErrStopTimedOut, d)
	}
	if err != nil {
		return fmt.Errorf("HEV TUN stop: %w", err)
	}
	return nil
}

// hevStart is the start of HEV TUN inside a session. It begins at the very start of StartSession, in
// its own goroutine, and the session joins it (await) once Xray is up. Starting hev is the slow part
// of a tunnel start that does not depend on Xray (a console process and a Wintun adapter on Windows,
// the administrator prompt on macOS), so it runs beside AmneziaWG and the loading of the Xray config
// instead of after them. hev only meets traffic once the host installs the routes, after the session.
type hevStart struct {
	c    *CoreController
	gen  uint64
	cfg  *sessionPlanHev
	tun  hevTunnel
	done chan struct{} // closed when Start returned
	err  error         // Start's result; valid once done is closed

	mu        sync.Mutex
	cancelled bool
}

// beginSessionHev starts HEV TUN for start attempt gen without waiting for it.
func (c *CoreController) beginSessionHev(gen uint64, cfg *sessionPlanHev) *hevStart {
	h := &hevStart{c: c, gen: gen, cfg: cfg, tun: hevTun, done: make(chan struct{})}
	c.mu.Lock()
	if c.gen != gen || c.state != stateStarting {
		c.mu.Unlock()
		h.err = errStartAborted
		close(h.done)
		return h
	}
	if !claimHev(c, gen) {
		c.mu.Unlock()
		h.err = errors.New("HEV TUN is busy stopping the previous session")
		close(h.done)
		return h
	}
	c.mu.Unlock()
	go h.run()
	return h
}

func (h *hevStart) run() {
	defer close(h.done)
	h.mu.Lock()
	cancelled := h.cancelled
	h.mu.Unlock()
	if cancelled {
		h.err = errStartAborted
		return
	}
	opts := hevtun.Options{TunFd: h.cfg.TunFd, RunDirectory: h.cfg.RunDirectory, MacInterface: h.cfg.MacInterface}
	h.err = h.tun.Start(h.cfg.ConfigYAML, opts)
	if h.err != nil {
		return
	}
	h.mu.Lock()
	cancelled = h.cancelled
	h.mu.Unlock()
	if cancelled {
		// The session was abandoned while hev came up (a late answer to the macOS prompt, say).
		stopHevUnlessOwnedByOther(h.c, h.gen, h.tun, defaultStopTimeout)
	}
}

// cancel ends the start: hev is stopped now, or as soon as its Start returns.
func (h *hevStart) cancel() {
	h.mu.Lock()
	h.cancelled = true
	h.mu.Unlock()
	_ = stopHevIfOwned(h.c, h.gen, defaultStopTimeout)
}

// await joins the start and then waits for hev to be ready. On any failure it stops hev again before
// returning. A ForceStop that supersedes the start attempt ends the wait.
func (h *hevStart) await() error {
	c, gen := h.c, h.gen
	for waiting := true; waiting; {
		select {
		case <-h.done:
			waiting = false
		case <-time.After(hevReadyPoll):
			if c.superseded(gen) {
				h.cancel()
				return errStartAborted
			}
		}
	}
	if h.err != nil {
		if errors.Is(h.err, errStartAborted) {
			return errStartAborted
		}
		_ = stopHevIfOwned(c, gen, defaultStopTimeout)
		return fmt.Errorf("HEV TUN failed to start: %w", h.err)
	}
	if c.superseded(gen) {
		_ = stopHevIfOwned(c, gen, defaultStopTimeout)
		return errStartAborted
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
