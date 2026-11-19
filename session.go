// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ZloyRadetski/skipi-core/internal/lifecycle"
)

// Session states reported by CoreController.State and StateListener.
const (
	SessionIdle     = 0
	SessionStarting = 1
	SessionRunning  = 2
	SessionStopping = 3
)

// StateListener is told about every session state change. It is called synchronously on the
// goroutine that caused the change, after the controller released its lock, so it may call back
// into the controller. A panic in it is recovered; keep it quick.
type StateListener interface {
	OnStateChanged(state int, detail string)
}

type listenerBox struct{ l StateListener }

// SetStateListener registers the listener for state changes; nil clears it.
func (c *CoreController) SetStateListener(l StateListener) {
	if l == nil {
		c.stateListener.Store(nil)
		return
	}
	c.stateListener.Store(&listenerBox{l: l})
}

// State returns the current session state. It only takes the short lifecycle lock, so it never
// waits on a slow start or stop.
func (c *CoreController) State() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return int(c.state)
}

// notifyState tells the listener about a transition. Callers must not hold c.mu.
func (c *CoreController) notifyState(s lifecycleState, detail string) {
	box := c.stateListener.Load()
	if box == nil {
		return
	}
	defer func() { _ = recover() }()
	box.l.OnStateChanged(int(s), detail)
}

// Seams for the session start: tests replace the AmneziaWG start and the readiness deadline.
var (
	startAmneziaWgFn = StartAmneziaWg
	// awgReadyTimeout is how long StartSession waits for the AmneziaWG SOCKS listener.
	awgReadyTimeout = 8000 * time.Millisecond
)

const awgReadyPoll = 20 * time.Millisecond

type sessionPlan struct {
	XrayConfig    string          `json:"xrayConfig"`
	AmneziaWg     *sessionPlanAwg `json:"amneziaWg"`
	ConnectionLog bool            `json:"connectionLog"`
	Hev           *sessionPlanHev `json:"hev"`
}

type sessionPlanAwg struct {
	Config    string `json:"config"`
	SocksPort int    `json:"socksPort"`
}

func parseSessionPlan(planJSON string) (*sessionPlan, error) {
	var p sessionPlan
	if err := json.Unmarshal([]byte(planJSON), &p); err != nil {
		return nil, fmt.Errorf("invalid session plan: %w", err)
	}
	if strings.TrimSpace(p.XrayConfig) == "" {
		return nil, errors.New("session plan: xrayConfig is missing")
	}
	if p.AmneziaWg != nil {
		if p.AmneziaWg.SocksPort <= 0 {
			return nil, errors.New("session plan: amneziaWg.socksPort must be positive")
		}
		if strings.TrimSpace(p.AmneziaWg.Config) == "" {
			return nil, errors.New("session plan: amneziaWg.config must not be blank")
		}
	}
	if p.Hev != nil {
		if strings.TrimSpace(p.Hev.ConfigYAML) == "" {
			return nil, errors.New("session plan: hev.configYaml must not be blank")
		}
		if p.Hev.TunFd <= 0 {
			return nil, errors.New("session plan: hev.tunFd must be positive")
		}
	}
	return &p, nil
}

// StartSession starts the whole tunnel session from one plan JSON:
//
//	{"xrayConfig": "<xray json>", "amneziaWg": {"config": "<awg json>", "socksPort": 10808}, "connectionLog": true}
//
// amneziaWg is optional. With it, AmneziaWG starts first and Core waits until its local SOCKS
// listener accepts connections, then Xray starts. The optional "hev": {"configYaml": "<yaml>",
// "tunFd": N} starts HEV TUN last and waits (hevReadyTimeout) until it reports ready. Any failure
// stops what was started, in reverse. A later StopLoop, StopLoopWithTimeout or ForceStop stops
// HEV TUN, then Xray, then AmneziaWG.
func (c *CoreController) StartSession(planJSON string, tunFd int64) error {
	plan, err := parseSessionPlan(planJSON)
	if err != nil {
		return err
	}
	myGen, err := c.beginStart()
	if err != nil {
		return err
	}
	defer c.reapAbandonedStart(myGen)

	var runner *AmneziaWgRunner
	stopOwnAwg := func() {
		if runner != nil {
			stopAwgRunner(runner, defaultStopTimeout)
		}
	}
	if plan.AmneziaWg != nil {
		runner, err = c.startSessionAwg(myGen, plan.AmneziaWg, stopOwnAwg)
		if err != nil {
			stopOwnAwg()
			return err
		}
	}

	c.SetConnectionLogEnabled(plan.ConnectionLog)
	var afterXray func() error
	if plan.Hev != nil {
		afterXray = func() error { return c.startSessionHev(myGen, plan.Hev) }
	}
	if err := c.runStart(myGen, plan.XrayConfig, tunFd, plan.AmneziaWg != nil, stopOwnAwg, afterXray, plan.Hev != nil); err != nil {
		stopOwnAwg() // also covers a start that ForceStop aborted
		return err
	}
	return nil
}

// startSessionAwg starts the runner and waits for its SOCKS listener. It returns the runner it
// started. On any error the caller stops that runner; the controller is already back to idle
// unless ForceStop did that.
func (c *CoreController) startSessionAwg(gen uint64, cfg *sessionPlanAwg, stopOwnAwg func()) (*AmneziaWgRunner, error) {
	if err := startAmneziaWgFn(cfg.Config, cfg.SocksPort); err != nil {
		c.failStart(gen, err.Error())
		return nil, err
	}
	awgGlobalMu.Lock()
	runner := activeAwgRunner
	awgGlobalMu.Unlock()

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.SocksPort)
	deadline := time.Now().Add(awgReadyTimeout)
	for {
		if c.superseded(gen) {
			return runner, errStartAborted
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		conn, err := net.DialTimeout("tcp", addr, min(remaining, 250*time.Millisecond))
		if err == nil {
			_ = conn.Close()
			return runner, nil
		}
		time.Sleep(min(awgReadyPoll, max(time.Until(deadline), 0)))
	}
	err := fmt.Errorf("AmneziaWG SOCKS listener on port %d was not ready: timed out after %v", cfg.SocksPort, awgReadyTimeout)
	// Stop first, so the controller is idle only once AmneziaWG is gone.
	stopOwnAwg()
	c.failStart(gen, err.Error())
	return runner, err
}

// stopAwgRunner stops runner if it is still the active one, bounded by d. A runner that was
// replaced or stopped already (by ForceStop, say) is left alone, so a late cleanup never kills a
// newer session's tunnel.
func stopAwgRunner(runner *AmneziaWgRunner, d time.Duration) {
	awgGlobalMu.Lock()
	if activeAwgRunner != runner {
		awgGlobalMu.Unlock()
		return
	}
	activeAwgRunner = nil
	awgGlobalMu.Unlock()
	_, _ = lifecycle.RunBounded(func() error { return awgStop(runner) }, d, nil)
}
