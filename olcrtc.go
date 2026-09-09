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

// OlcRtcRoom handles room specified either as a scalar string or as an object with id.
type OlcRtcRoom struct {
	ID string
}

func (r *OlcRtcRoom) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		r.ID = s
		return nil
	}
	var m struct {
		ID string `yaml:"id"`
	}
	if err := unmarshal(&m); err == nil {
		r.ID = m.ID
		return nil
	}
	return nil
}

// OlcRtcConfigData models fields supported in YAML or flat configs.
type OlcRtcConfigData struct {
	Mode       string     `yaml:"mode"`
	Provider   string     `yaml:"provider"`
	Transport  string     `yaml:"transport"`
	RoomRaw    OlcRtcRoom `yaml:"room"`
	Room       string     `yaml:"-"`
	Key        string     `yaml:"key"`
	DNS        string     `yaml:"dns"`
	Local      string     `yaml:"socks5_listen"`
	Socks5User string     `yaml:"socks5_user"`
	Socks5Pass string     `yaml:"socks5_pass"`
	Channel    string     `yaml:"channel"`
	Token      string     `yaml:"token"`

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
		User string `yaml:"user"`
		Pass string `yaml:"pass"`
	} `yaml:"socks"`

	VP8 struct {
		FPS       int `yaml:"fps"`
		BatchSize int `yaml:"batch_size"`
	} `yaml:"vp8"`
	SEI struct {
		FPS          int `yaml:"fps"`
		BatchSize    int `yaml:"batch_size"`
		FragmentSize int `yaml:"fragment_size"`
		AckTimeoutMS int `yaml:"ack_timeout_ms"`
	} `yaml:"sei"`
	Video struct {
		Width      int    `yaml:"width"`
		Height     int    `yaml:"height"`
		FPS        int    `yaml:"fps"`
		Codec      string `yaml:"codec"`
		QRSize     int    `yaml:"qr_size"`
		QRRecovery string `yaml:"qr_recovery"`
		TileModule int    `yaml:"tile_module"`
		TileRS     int    `yaml:"tile_rs"`
	} `yaml:"video"`
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
			case "id":
				if cfg.Room == "" {
					cfg.Room = v
				}
			case "key":
				cfg.Key = v
			case "dns":
				cfg.DNS = v
			case "socks5_listen":
				cfg.Local = v
			case "socks5_user", "socks_user", "user":
				cfg.Socks5User = v
			case "socks5_pass", "socks_pass", "pass", "password":
				cfg.Socks5Pass = v
			case "channel":
				cfg.Channel = v
			case "token":
				cfg.Token = v
			case "vp8_fps", "vp8-fps":
				if n, err := strconv.Atoi(v); err == nil {
					cfg.VP8.FPS = n
				}
			case "vp8_batch", "vp8-batch", "vp8_batch_size":
				if n, err := strconv.Atoi(v); err == nil {
					cfg.VP8.BatchSize = n
				}
			case "sei_fps", "sei-fps":
				if n, err := strconv.Atoi(v); err == nil {
					cfg.SEI.FPS = n
				}
			case "sei_batch", "sei-batch":
				if n, err := strconv.Atoi(v); err == nil {
					cfg.SEI.BatchSize = n
				}
			}
		}
	} else {
		if cfg.Room == "" && cfg.RoomRaw.ID != "" {
			cfg.Room = cfg.RoomRaw.ID
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

	// If transport has payload like datachannel<...> or vp8channel[...], extract base transport & payload
	var payloadStr string
	if openIdx := strings.IndexAny(cfg.Transport, "<["); openIdx >= 0 {
		closeChar := ">"
		if cfg.Transport[openIdx] == '[' {
			closeChar = "]"
		}
		closeIdx := strings.LastIndex(cfg.Transport, closeChar)
		if closeIdx > openIdx {
			payloadStr = cfg.Transport[openIdx+1 : closeIdx]
		}
		cfg.Transport = strings.TrimSpace(cfg.Transport[:openIdx])
	}

	if payloadStr != "" {
		for _, part := range strings.Split(payloadStr, "&") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			kv := strings.SplitN(part, "=", 2)
			k := strings.ToLower(strings.TrimSpace(kv[0]))
			v := ""
			if len(kv) == 2 {
				v = strings.TrimSpace(kv[1])
			}
			switch k {
			case "vp8-fps", "fps":
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					if cfg.VP8.FPS <= 0 {
						cfg.VP8.FPS = n
					}
					if cfg.SEI.FPS <= 0 {
						cfg.SEI.FPS = n
					}
				}
			case "vp8-batch", "batch":
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					if cfg.VP8.BatchSize <= 0 {
						cfg.VP8.BatchSize = n
					}
					if cfg.SEI.BatchSize <= 0 {
						cfg.SEI.BatchSize = n
					}
				}
			case "frag", "fragment_size":
				if n, err := strconv.Atoi(v); err == nil && n > 0 && cfg.SEI.FragmentSize <= 0 {
					cfg.SEI.FragmentSize = n
				}
			case "ack-ms", "ack_timeout_ms":
				if n, err := strconv.Atoi(v); err == nil && n > 0 && cfg.SEI.AckTimeoutMS <= 0 {
					cfg.SEI.AckTimeoutMS = n
				}
			case "video-w", "width":
				if n, err := strconv.Atoi(v); err == nil && n > 0 && cfg.Video.Width <= 0 {
					cfg.Video.Width = n
				}
			case "video-h", "height":
				if n, err := strconv.Atoi(v); err == nil && n > 0 && cfg.Video.Height <= 0 {
					cfg.Video.Height = n
				}
			case "video-fps":
				if n, err := strconv.Atoi(v); err == nil && n > 0 && cfg.Video.FPS <= 0 {
					cfg.Video.FPS = n
				}
			case "video-codec", "codec":
				if v != "" && cfg.Video.Codec == "" {
					cfg.Video.Codec = v
				}
			case "video-qr-size", "qr_size":
				if n, err := strconv.Atoi(v); err == nil && n > 0 && cfg.Video.QRSize <= 0 {
					cfg.Video.QRSize = n
				}
			case "video-qr-recovery", "qr_recovery":
				if v != "" && cfg.Video.QRRecovery == "" {
					cfg.Video.QRRecovery = v
				}
			case "video-tile-module", "tile_module":
				if n, err := strconv.Atoi(v); err == nil && n > 0 && cfg.Video.TileModule <= 0 {
					cfg.Video.TileModule = n
				}
			case "video-tile-rs", "tile_rs":
				if n, err := strconv.Atoi(v); err == nil && cfg.Video.TileRS <= 0 {
					cfg.Video.TileRS = n
				}
			}
		}
	}

	// Normalize room
	if cfg.Room == "" && cfg.RoomRaw.ID != "" {
		cfg.Room = cfg.RoomRaw.ID
	}
	if cfg.Room == "" && cfg.RoomObj.ID != "" {
		cfg.Room = cfg.RoomObj.ID
	}

	// Normalize key
	if cfg.Key == "" && cfg.Crypto.Key != "" {
		cfg.Key = cfg.Crypto.Key
	}

	// Normalize SOCKS credentials
	if cfg.Socks5User == "" && cfg.Socks.User != "" {
		cfg.Socks5User = cfg.Socks.User
	}
	if cfg.Socks5Pass == "" && cfg.Socks.Pass != "" {
		cfg.Socks5Pass = cfg.Socks.Pass
	}

	// Normalize DNS. The runtime must never silently choose a public resolver
	// when the embedding app supplied no resolver: that can bypass the VPN's DNS
	// policy and makes a configuration error look like a working connection.
	if cfg.DNS == "" && cfg.Net.DNS != "" {
		cfg.DNS = cfg.Net.DNS
	}
	normalizedDNS, err := normalizeOlcRtcDNS(cfg.DNS)
	if err != nil {
		return nil, err
	}
	cfg.DNS = normalizedDNS

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

// normalizeOlcRtcDNS accepts a plain DNS host or host:port. olcrtc's mobile
// runtime expects a raw resolver endpoint, not a DoH/DoQ URL.
func normalizeOlcRtcDNS(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("olcrtc dns is required")
	}
	if strings.Contains(raw, "://") {
		return "", fmt.Errorf("olcrtc dns must be a raw host:port, got %q", raw)
	}
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw, nil
	}

	// A bare IPv6 literal needs brackets before adding the default port.
	if ip := net.ParseIP(strings.Trim(raw, "[]")); ip != nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	if strings.Contains(raw, ":") {
		return "", fmt.Errorf("invalid olcrtc dns endpoint %q", raw)
	}
	return net.JoinHostPort(raw, "53"), nil
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

	switch strings.ToLower(cfg.Transport) {
	case "vp8channel":
		fps := cfg.VP8.FPS
		if fps <= 0 {
			fps = 30
		}
		batch := cfg.VP8.BatchSize
		if batch <= 1 {
			batch = 64
		}
		if err := rt.SetVP8Options(fps, batch); err != nil {
			return fmt.Errorf("set vp8 options: %w", err)
		}
	case "seichannel":
		fps := cfg.SEI.FPS
		if fps <= 0 {
			fps = 30
		}
		batch := cfg.SEI.BatchSize
		if batch <= 1 {
			batch = 64
		}
		frag := cfg.SEI.FragmentSize
		if frag <= 0 {
			frag = 900
		}
		ackMs := cfg.SEI.AckTimeoutMS
		if ackMs <= 0 {
			ackMs = 2000
		}
		if err := rt.SetSEIOptions(fps, batch, frag, ackMs); err != nil {
			return fmt.Errorf("set sei options: %w", err)
		}
	case "videochannel":
		w := cfg.Video.Width
		if w <= 0 {
			w = 1920
		}
		h := cfg.Video.Height
		if h <= 0 {
			h = 1080
		}
		fps := cfg.Video.FPS
		if fps <= 0 {
			fps = 30
		}
		codec := cfg.Video.Codec
		if codec == "" {
			codec = "qrcode"
		}
		qrSize := cfg.Video.QRSize
		qrRec := cfg.Video.QRRecovery
		if qrRec == "" {
			qrRec = "low"
		}
		tileMod := cfg.Video.TileModule
		if tileMod <= 0 {
			tileMod = 4
		}
		tileRS := cfg.Video.TileRS
		if err := rt.SetVideoOptions(w, h, fps, qrSize, qrRec, codec, tileMod, tileRS); err != nil {
			return fmt.Errorf("set video options: %w", err)
		}
	}
	if err := rt.SetRoom(cfg.Room); err != nil {
		return fmt.Errorf("set room: %w", err)
	}
	if err := rt.SetKey(cfg.Key); err != nil {
		return fmt.Errorf("set key: %w", err)
	}
	if err := rt.SetDNS(cfg.DNS); err != nil {
		return fmt.Errorf("set dns %q: %w", cfg.DNS, err)
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

	if cfg.Socks5User != "" || cfg.Socks5Pass != "" {
		if err := rt.SetSocksCredentials(cfg.Socks5User, cfg.Socks5Pass); err != nil {
			return fmt.Errorf("set socks credentials: %w", err)
		}
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

// WaitOlcRtcReady waits up to timeoutMillis for the active OLCRTC client runtime to become ready.
func WaitOlcRtcReady(timeoutMillis int) error {
	olcrtcMu.Lock()
	rt := olcrtcRuntime
	olcrtcMu.Unlock()

	if rt == nil {
		return errors.New("olcrtc runtime is not active")
	}
	return rt.WaitReady(timeoutMillis)
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
