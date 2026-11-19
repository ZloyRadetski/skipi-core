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

// StartAmneziaWg creates and starts an AmneziaWG tunnel using github.com/amnezia-vpn/amneziawg-go/v3.
func StartAmneziaWg(configJSON string, socksPort int) error {
	awgGlobalMu.Lock()
	defer awgGlobalMu.Unlock()

	if activeAwgRunner != nil && activeAwgRunner.running {
		old := activeAwgRunner
		activeAwgRunner = nil
		_, _ = lifecycle.RunBounded(func() error { return awgStop(old) }, defaultStopTimeout, nil)
	}

	settings, err := ParseAmneziaWgSettings(configJSON)
	if err != nil {
		return fmt.Errorf("failed to parse AmneziaWG settings: %w", err)
	}

	runner, err := NewAmneziaWgRunner(settings, socksPort)
	if err != nil {
		return fmt.Errorf("failed to initialize AmneziaWG runner: %w", err)
	}

	if err := runner.Start(); err != nil {
		return fmt.Errorf("failed to start AmneziaWG runner: %w", err)
	}

	activeAwgRunner = runner
	return nil
}

// awgStop closes one runner. It is a variable so tests can simulate a Close that hangs.
var awgStop = func(r *AmneziaWgRunner) error { return r.Stop() }

// StopAmneziaWg stops the currently active AmneziaWG runner, giving up after the default timeout.
func StopAmneziaWg() error {
	return StopAmneziaWgWithTimeout(0)
}

// StopAmneziaWgWithTimeout stops the active runner and waits at most timeoutMillis for it
// (non-positive: 5000 ms). A runner whose Stop hangs is detached anyway and counted in
// AbandonedInstances until Stop returns; the error then wraps ErrStopTimedOut.
func StopAmneziaWgWithTimeout(timeoutMillis int64) error {
	d := defaultStopTimeout
	if timeoutMillis > 0 {
		d = time.Duration(timeoutMillis) * time.Millisecond
	}

	awgGlobalMu.Lock()
	runner := activeAwgRunner
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
