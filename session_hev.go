// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ZloyRadetski/skipi-core/internal/hevtun"
	"github.com/ZloyRadetski/skipi-core/internal/lifecycle"
)

// hevTunnel is the HEV TUN the session drives. The production value forwards to internal/hevtun
// (cgo on Android, a stub elsewhere); tests substitute a fake.
type hevTunnel interface {
	Start(configYAML string, tunFd int) error
	WaitReady(timeout time.Duration) error
	Stop() error
	Stats() (txPackets, txBytes, rxPackets, rxBytes uint64)
	Running() bool
}

type realHevTunnel struct{}

func (realHevTunnel) Start(configYAML string, tunFd int) error {
	return hevtun.Start(configYAML, tunFd)
}
func (realHevTunnel) WaitReady(timeout time.Duration) error   { return hevtun.WaitReady(timeout) }
func (realHevTunnel) Stop() error                             { return hevtun.Stop() }
func (realHevTunnel) Stats() (uint64, uint64, uint64, uint64) { return hevtun.Stats() }
func (realHevTunnel) Running() bool                           { return hevtun.Running() }

// Seams for the HEV TUN part of a session.
var (
	hevTun hevTunnel = realHevTunnel{}
	// hevReadyTimeout is how long StartSession waits for HEV TUN to report readiness.
	hevReadyTimeout = 5000 * time.Millisecond
)

// hevReadyPoll is the slice StartSession waits in, so a ForceStop ends the wait promptly.
const hevReadyPoll = 100 * time.Millisecond

type sessionPlanHev struct {
	ConfigYAML string `json:"configYaml"`
	TunFd      int    `json:"tunFd"`
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
	if err := hevTun.Start(cfg.ConfigYAML, cfg.TunFd); err != nil {
		_ = stopHevBounded(defaultStopTimeout, nil)
		return fmt.Errorf("HEV TUN failed to start: %w", err)
	}
	deadline := time.Now().Add(hevReadyTimeout)
	for {
		if c.superseded(gen) {
			_ = stopHevBounded(defaultStopTimeout, nil)
			return errStartAborted
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			_ = stopHevBounded(defaultStopTimeout, nil)
			return fmt.Errorf("HEV TUN was not ready: timed out after %v", hevReadyTimeout)
		}
		err := hevTun.WaitReady(min(remaining, hevReadyPoll))
		if err == nil {
			return nil
		}
		if errors.Is(err, hevtun.ErrReadyTimeout) {
			continue
		}
		_ = stopHevBounded(defaultStopTimeout, nil)
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
