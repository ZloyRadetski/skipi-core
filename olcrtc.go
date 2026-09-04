// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/openlibrecommunity/olcrtc/mobile"
	"gopkg.in/yaml.v2"
)

// SocketProtector matches the gomobile interface for Android VpnService.protect(int).
type SocketProtector interface {
	Protect(fd int) bool
}

// Global state for OLCRTC lifecycle
var (
	olcrtcMu        sync.Mutex
	olcrtcRuntime   *mobile.Runtime
	olcrtcProtector SocketProtector
)

// SetOlcRtcSocketProtector registers an Android SocketProtector for WebRTC traffic.
func SetOlcRtcSocketProtector(p SocketProtector) {
	olcrtcMu.Lock()
	defer olcrtcMu.Unlock()
	olcrtcProtector = p
	if olcrtcRuntime != nil && p != nil {
		olcrtcRuntime.SetProtector(p)
	}
}

// OlcRtcConfigData models fields supported in YAML or flat configs.
type OlcRtcConfigData struct {
	Mode      string `yaml:"mode"`
	Provider  string `yaml:"provider"`
	Transport string `yaml:"transport"`
	Room      string `yaml:"room"`
	Key       string `yaml:"key"`
	DNS       string `yaml:"dns"`
	Local     string `yaml:"socks5_listen"`
	Channel   string `yaml:"channel"`
	Token     string `yaml:"token"`

	Auth struct {
		Provider string `yaml:"provider"`
		Token    string `yaml:"token"`
	} `yaml:"auth"`
	RoomObj struct {
		ID      string `yaml:"id"`
		Channel string `yaml:"channel"`
	} `yaml:"room_obj"`
	Crypto struct {
		Key string `yaml:"key"`
	} `yaml:"crypto"`
	Net struct {
		Transport string `yaml:"transport"`
		DNS       string `yaml:"dns"`
	} `yaml:"net"`
	Socks struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"socks"`
}

// ParseOlcRtcOptions parses YAML and extracts normalized parameters.
func ParseOlcRtcOptions(rawYaml string, fallbackPort int) (*OlcRtcConfigData, error) {
	var cfg OlcRtcConfigData
	if err := yaml.Unmarshal([]byte(rawYaml), &cfg); err != nil {
		// Fallback simple line-based parsing if YAML parsing fails
		lines := strings.Split(rawYaml, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(parts[0]))
			v := strings.TrimSpace(parts[1])
			switch k {
			case "provider":
				cfg.Provider = v
			case "transport":
				cfg.Transport = v
			case "room":
				cfg.Room = v
			case "key":
				cfg.Key = v
			case "dns":
				cfg.DNS = v
			case "socks5_listen":
				cfg.Local = v
			case "channel":
				cfg.Channel = v
			case "token":
				cfg.Token = v
			}
		}
	}

	// Normalize provider
	if cfg.Provider == "" && cfg.Auth.Provider != "" {
		cfg.Provider = cfg.Auth.Provider
	}
	if cfg.Provider == "" {
		cfg.Provider = "jitsi"
	}

	// Normalize transport
	if cfg.Transport == "" && cfg.Net.Transport != "" {
		cfg.Transport = cfg.Net.Transport
	}
	if cfg.Transport == "" {
		cfg.Transport = "datachannel"
	}
	// If transport has payload like datachannel[...] or vp8channel[...], extract base transport
	if idx := strings.Index(cfg.Transport, "["); idx > 0 {
		cfg.Transport = cfg.Transport[:idx]
	}

	// Normalize room
	if cfg.Room == "" && cfg.RoomObj.ID != "" {
		cfg.Room = cfg.RoomObj.ID
	}

	// Normalize key
	if cfg.Key == "" && cfg.Crypto.Key != "" {
		cfg.Key = cfg.Crypto.Key
	}

	// Normalize DNS
	if cfg.DNS == "" && cfg.Net.DNS != "" {
		cfg.DNS = cfg.Net.DNS
	}
	if cfg.DNS == "" {
		cfg.DNS = "8.8.8.8:53"
	}
	if !strings.Contains(cfg.DNS, ":") {
		cfg.DNS = net.JoinHostPort(cfg.DNS, "53")
	}

	// Normalize socks port
	if cfg.Socks.Port <= 0 {
		if cfg.Local != "" {
			_, portStr, err := net.SplitHostPort(cfg.Local)
			if err == nil {
				if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
					cfg.Socks.Port = p
				}
			}
		}
	}
	if cfg.Socks.Port <= 0 {
		if fallbackPort > 0 {
			cfg.Socks.Port = fallbackPort
		} else {
			cfg.Socks.Port = 10808
		}
	}

	return &cfg, nil
}

// StartOlcRtc starts the OLCRTC client runtime using openlibrecommunity/olcrtc/mobile.
func StartOlcRtc(configYaml string, socksPort int) error {
	olcrtcMu.Lock()
	defer olcrtcMu.Unlock()

	if olcrtcRuntime != nil && olcrtcRuntime.IsRunning() {
		_ = olcrtcRuntime.Stop(3000)
		olcrtcRuntime = nil
	}

	cfg, err := ParseOlcRtcOptions(configYaml, socksPort)
	if err != nil {
		return fmt.Errorf("failed to parse olcrtc config: %w", err)
	}

	if cfg.Room == "" {
		return errors.New("olcrtc room is required")
	}
	if cfg.Key == "" {
		return errors.New("olcrtc key is required")
	}

	rt := mobile.New()
	if err := rt.SetProvider(cfg.Provider); err != nil {
		return fmt.Errorf("set provider %q: %w", cfg.Provider, err)
	}
	if err := rt.SetTransport(cfg.Transport); err != nil {
		return fmt.Errorf("set transport %q: %w", cfg.Transport, err)
	}
	if err := rt.SetRoom(cfg.Room); err != nil {
		return fmt.Errorf("set room: %w", err)
	}
	if err := rt.SetKey(cfg.Key); err != nil {
		return fmt.Errorf("set key: %w", err)
	}
	if cfg.DNS != "" {
		_ = rt.SetDNS(cfg.DNS)
	}
	if cfg.Channel != "" {
		rt.SetChannel(cfg.Channel)
	}
	if cfg.Token != "" {
		rt.SetProviderToken(cfg.Token)
	}

	_ = rt.SetSocksListenHost("127.0.0.1")
	if err := rt.SetSocksPort(cfg.Socks.Port); err != nil {
		return fmt.Errorf("set socks port %d: %w", cfg.Socks.Port, err)
	}

	if olcrtcProtector != nil {
		rt.SetProtector(olcrtcProtector)
	}

	if err := rt.Start(); err != nil {
		return fmt.Errorf("failed to start olcrtc runtime: %w", err)
	}

	olcrtcRuntime = rt
	return nil
}

// StopOlcRtc stops any active OLCRTC client runtime.
func StopOlcRtc() error {
	olcrtcMu.Lock()
	defer olcrtcMu.Unlock()

	if olcrtcRuntime == nil {
		return nil
	}
	err := olcrtcRuntime.Stop(5000)
	olcrtcRuntime = nil
	return err
}

// IsOlcRtcRunning returns true if the OLCRTC client is currently active.
func IsOlcRtcRunning() bool {
	olcrtcMu.Lock()
	defer olcrtcMu.Unlock()
	return olcrtcRuntime != nil && olcrtcRuntime.IsRunning()
}

// OlcRtcState returns the current lifecycle state of OLCRTC runtime.
func OlcRtcState() string {
	olcrtcMu.Lock()
	defer olcrtcMu.Unlock()
	if olcrtcRuntime == nil {
		return "stopped"
	}
	return olcrtcRuntime.State()
}
