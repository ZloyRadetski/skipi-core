// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ZloyRadetski/skipi-core/internal/amneziawg"
	"github.com/ZloyRadetski/skipi-core/internal/lifecycle"
)

// AmneziaWgPeer models a WireGuard/AmneziaWG peer in Xray configuration.
type AmneziaWgPeer struct {
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey"`
	Endpoint     string   `json:"endpoint"`
	KeepAlive    any      `json:"keepAlive"`
	AllowedIPs   []string `json:"allowedIPs"`
}

// AmneziaWgSettings models the Xray WireGuard outbound settings including AmneziaWG obfuscation fields.
type AmneziaWgSettings struct {
	SecretKey string           `json:"secretKey"`
	Address   any              `json:"address"`
	Peers     []*AmneziaWgPeer `json:"peers"`
	MTU       int              `json:"mtu"`
	// DNSServers is a runtime-only list of raw IP resolvers for the internal
	// netstack. It deliberately is not an Xray WireGuard setting.
	DNSServers []string `json:"dnsServers"`
	// SocksUser and SocksPass are runtime-only too: when set, the local SOCKS listener asks every
	// client for them (RFC 1929), so no other program on the device can use the tunnel's exit.
	SocksUser string `json:"socksUser"`
	SocksPass string `json:"socksPass"`

	// AmneziaWG specific fields:
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	S3   int    `json:"s3"`
	S4   int    `json:"s4"`
	H1   any    `json:"h1"`
	H2   any    `json:"h2"`
	H3   any    `json:"h3"`
	H4   any    `json:"h4"`
	I1   string `json:"i1"`
	I2   string `json:"i2"`
	I3   string `json:"i3"`
	I4   string `json:"i4"`
	I5   string `json:"i5"`

	// AmneziaWG 3.0. Ranges are a number or an "N-M" string, 0..65535.
	HeaderProtectionKey    string `json:"headerProtectionKey"`
	ContentPaddingAddition any    `json:"contentPaddingAddition"`
	RekeyAfterTime         any    `json:"rekeyAfterTime"`
	RekeyTimeout           any    `json:"rekeyTimeout"`
	RejectAfterTime        any    `json:"rejectAfterTime"`
	KeepaliveTimeout       any    `json:"keepaliveTimeout"`
	MaxHandshakeAttempts   any    `json:"maxHandshakeAttempts"`

	// AmneziaWG 3.1 flags: true/false, "on"/"off" (any letter case) or 1/0.
	RandomTrailers any `json:"randomTrailers"`
	DisableCookies any `json:"disableCookies"`
}

// Process-wide AmneziaWG state: the active runner and the Android socket protector.
var (
	awgGlobalMu        sync.Mutex
	activeAwgRunner    *AmneziaWgRunner
	awgProtectorMu     sync.RWMutex
	awgSocketProtector SocketProtector
)

// SetAmneziaWgSocketProtector registers Android's VpnService.protect bridge
// for the UDP sockets used by the AmneziaWG peer. Without it the peer's own
// packets can be routed back into the VPN TUN and never complete a handshake.
func SetAmneziaWgSocketProtector(p SocketProtector) {
	awgProtectorMu.Lock()
	defer awgProtectorMu.Unlock()
	awgSocketProtector = p
}

func currentAmneziaWgSocketProtector() SocketProtector {
	awgProtectorMu.RLock()
	defer awgProtectorMu.RUnlock()
	return awgSocketProtector
}

// ParseAmneziaWgSettings extracts AmneziaWgSettings from full Xray config, outbound json, or settings json.
func ParseAmneziaWgSettings(rawJSON string) (*AmneziaWgSettings, error) {
	var generic map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &generic); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}

	// 1. Direct settings
	if _, ok := generic["secretKey"]; ok {
		var s AmneziaWgSettings
		if err := json.Unmarshal([]byte(rawJSON), &s); err == nil {
			return &s, nil
		}
	}

	// 2. Outbound object: {"protocol": "wireguard", "settings": {...}}
	if settingsRaw, ok := generic["settings"]; ok {
		bytes, err := json.Marshal(settingsRaw)
		if err == nil {
			var s AmneziaWgSettings
			if err := json.Unmarshal(bytes, &s); err == nil && s.SecretKey != "" {
				return &s, nil
			}
		}
	}

	// 3. Full Xray config: {"outbounds": [...]}
	if outboundsRaw, ok := generic["outbounds"].([]any); ok {
		for _, ob := range outboundsRaw {
			if obMap, ok := ob.(map[string]any); ok {
				if proto, ok := obMap["protocol"].(string); ok && (proto == "wireguard" || proto == "amneziawg") {
					if settingsRaw, ok := obMap["settings"]; ok {
						bytes, err := json.Marshal(settingsRaw)
						if err == nil {
							var s AmneziaWgSettings
							if err := json.Unmarshal(bytes, &s); err == nil && s.SecretKey != "" {
								return &s, nil
							}
						}
					}
				}
			}
		}
	}

	return nil, errors.New("no wireguard/amneziawg outbound settings found in json")
}

// ErrAmneziaWgInUse is returned by StartAmneziaWg while a session owns the runner: a probe must
// not take the tunnel's runner away.
var ErrAmneziaWgInUse = errors.New("AmneziaWG is in use by the running session")

// errAwgStartOvertaken is returned by a start that a stop overtook while the runner came up.
var errAwgStartOvertaken = errors.New("AmneziaWG start was cancelled by a stop")

var (
	// awgStartMu serializes starts. It is held while a runner resolves its peer and comes up;
	// awgGlobalMu is not, so stops and state reads never wait for that.
	awgStartMu sync.Mutex
	// awgGen is bumped by every stop (guarded by awgGlobalMu); a start that sees it changed when
	// it is ready to publish its runner stops that runner instead.
	awgGen uint64
	// awgStartingForSession tells a probe's stop to leave a session's start in flight alone.
	awgStartingForSession bool
)

// buildAwgRunner parses the config and brings a runner up: the slow part of a start. Tests replace it.
var buildAwgRunner = func(configJSON string, socksPort int) (*AmneziaWgRunner, error) {
	settings, err := ParseAmneziaWgSettings(configJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AmneziaWG settings: %w", err)
	}
	runner, err := NewAmneziaWgRunner(settings, socksPort)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AmneziaWG runner: %w", err)
	}
	if err := runner.Start(); err != nil {
		return nil, fmt.Errorf("failed to start AmneziaWG runner: %w", err)
	}
	return runner, nil
}

// StartAmneziaWg creates and starts an AmneziaWG tunnel using github.com/amnezia-vpn/amneziawg-go/v3.
// It replaces a runner started the same way, but never the runner of a running session: then it
// fails with ErrAmneziaWgInUse.
func StartAmneziaWg(configJSON string, socksPort int) error {
	return startAmneziaWg(configJSON, socksPort, false)
}

// startSessionAmneziaWg starts the runner a session owns; only that session's stop ends it.
func startSessionAmneziaWg(configJSON string, socksPort int) error {
	return startAmneziaWg(configJSON, socksPort, true)
}

func startAmneziaWg(configJSON string, socksPort int, forSession bool) error {
	awgStartMu.Lock()
	defer awgStartMu.Unlock()

	awgGlobalMu.Lock()
	old := activeAwgRunner
	if old != nil && old.sessionOwned && !forSession {
		awgGlobalMu.Unlock()
		return ErrAmneziaWgInUse
	}
	activeAwgRunner = nil
	awgGen++
	myGen := awgGen
	awgStartingForSession = forSession
	awgGlobalMu.Unlock()
	if old != nil {
		_, _ = lifecycle.RunBounded(func() error { return awgStop(old) }, defaultStopTimeout, nil)
	}

	runner, err := buildAwgRunner(configJSON, socksPort)
	if err != nil {
		return err
	}

	awgGlobalMu.Lock()
	if awgGen != myGen {
		awgGlobalMu.Unlock()
		_, _ = lifecycle.RunBounded(func() error { return awgStop(runner) }, defaultStopTimeout, nil)
		return errAwgStartOvertaken
	}
	runner.sessionOwned = forSession
	activeAwgRunner = runner
	awgGlobalMu.Unlock()
	return nil
}

// awgStop closes one runner. It is a variable so tests can simulate a Close that hangs.
var awgStop = func(r *AmneziaWgRunner) error { return r.Stop() }

// StopAmneziaWg stops the runner StartAmneziaWg started, giving up after the default timeout.
func StopAmneziaWg() error {
	return StopAmneziaWgWithTimeout(0)
}

// StopAmneziaWgWithTimeout stops the runner StartAmneziaWg started and waits at most timeoutMillis
// for it (non-positive: 5000 ms); a start of one in flight fails. A session's runner is left alone:
// its session stops it. A runner whose Stop hangs is detached anyway and counted in
// AbandonedInstances until Stop returns; the error then wraps ErrStopTimedOut.
func StopAmneziaWgWithTimeout(timeoutMillis int64) error {
	return stopAmneziaWg(timeoutMillis, false)
}

// stopAnyAmneziaWg is the stop of ForceStop: whoever owns the runner, it goes.
func stopAnyAmneziaWg(timeoutMillis int64) error {
	return stopAmneziaWg(timeoutMillis, true)
}

func stopAmneziaWg(timeoutMillis int64, evenSession bool) error {
	d := defaultStopTimeout
	if timeoutMillis > 0 {
		d = time.Duration(timeoutMillis) * time.Millisecond
	}

	awgGlobalMu.Lock()
	runner := activeAwgRunner
	if runner != nil && runner.sessionOwned && !evenSession {
		awgGlobalMu.Unlock()
		return nil
	}
	if evenSession || !awgStartingForSession {
		awgGen++
	}
	activeAwgRunner = nil
	awgGlobalMu.Unlock()
	if runner == nil {
		return nil
	}

	err, timedOut := lifecycle.RunBounded(func() error { return awgStop(runner) }, d, nil)
	if timedOut {
		return fmt.Errorf("%w: AmneziaWG runner did not stop within %v", ErrStopTimedOut, d)
	}
	return err
}

// IsAmneziaWgRunning reports whether AmneziaWG is currently active.
func IsAmneziaWgRunning() bool {
	awgGlobalMu.Lock()
	defer awgGlobalMu.Unlock()
	return activeAwgRunner != nil && activeAwgRunner.running
}

// RewriteWireguardOutboundToSocks rewrites wireguard/amneziawg outbounds in Xray JSON to point to a local SOCKS5 listener.
func RewriteWireguardOutboundToSocks(rawJSON string, socksPort int) string {
	return amneziawg.RewriteOutboundToSocks(rawJSON, socksPort)
}
