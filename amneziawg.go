// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
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

	// AmneziaWG specific fields:
	Jc   int `json:"jc"`
	Jmin int `json:"jmin"`
	Jmax int `json:"jmax"`
	S1   int `json:"s1"`
	S2   int `json:"s2"`
	S3   int `json:"s3"`
	S4   int `json:"s4"`
	H1   any `json:"h1"`
	H2   any `json:"h2"`
	H3   any `json:"h3"`
	H4   any `json:"h4"`
}

// HasAmneziaParams returns true if any AmneziaWG obfuscation parameter is configured.
func (s *AmneziaWgSettings) HasAmneziaParams() bool {
	if s.Jc > 0 || s.Jmin > 0 || s.Jmax > 0 || s.S1 > 0 || s.S2 > 0 || s.S3 > 0 || s.S4 > 0 {
		return true
	}
	if stringVal(s.H1) != "" && stringVal(s.H1) != "0" {
		return true
	}
	if stringVal(s.H2) != "" && stringVal(s.H2) != "0" {
		return true
	}
	if stringVal(s.H3) != "" && stringVal(s.H3) != "0" {
		return true
	}
	if stringVal(s.H4) != "" && stringVal(s.H4) != "0" {
		return true
	}
	return false
}

func stringVal(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val)
	case float64:
		return strconv.FormatInt(int64(val), 10)
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// decodeKeyToHex normalizes a WireGuard key from Base64 or Hex to 32-byte Hex.
func decodeKeyToHex(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty key")
	}
	if len(raw) == 64 {
		if _, err := hex.DecodeString(raw); err == nil {
			return strings.ToLower(raw), nil
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		rawNoPad := strings.TrimRight(raw, "=")
		decoded, err = base64.RawStdEncoding.DecodeString(rawNoPad)
		if err != nil {
			decoded, err = base64.RawURLEncoding.DecodeString(rawNoPad)
		}
	}
	if err != nil {
		return "", fmt.Errorf("decode key failed: %w", err)
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("key length must be 32 bytes, got %d", len(decoded))
	}
	return hex.EncodeToString(decoded), nil
}

// BuildIpcConfig builds the AmneziaWG UAPI IPC configuration string.
func (s *AmneziaWgSettings) BuildIpcConfig() (string, error) {
	privHex, err := decodeKeyToHex(s.SecretKey)
	if err != nil {
		return "", fmt.Errorf("invalid secret key: %w", err)
	}

	var b strings.Builder
	b.WriteString("private_key=" + privHex + "\n")

	if s.Jc > 0 {
		b.WriteString(fmt.Sprintf("jc=%d\n", s.Jc))
	}
	if s.Jmin > 0 {
		b.WriteString(fmt.Sprintf("jmin=%d\n", s.Jmin))
	}
	if s.Jmax > 0 {
		b.WriteString(fmt.Sprintf("jmax=%d\n", s.Jmax))
	}
	if s.S1 > 0 {
		b.WriteString(fmt.Sprintf("s1=%d\n", s.S1))
	}
	if s.S2 > 0 {
		b.WriteString(fmt.Sprintf("s2=%d\n", s.S2))
	}
	if s.S3 > 0 {
		b.WriteString(fmt.Sprintf("s3=%d\n", s.S3))
	}
	if s.S4 > 0 {
		b.WriteString(fmt.Sprintf("s4=%d\n", s.S4))
	}

	if h1 := stringVal(s.H1); h1 != "" && h1 != "0" {
		b.WriteString("h1=" + h1 + "\n")
	}
	if h2 := stringVal(s.H2); h2 != "" && h2 != "0" {
		b.WriteString("h2=" + h2 + "\n")
	}
	if h3 := stringVal(s.H3); h3 != "" && h3 != "0" {
		b.WriteString("h3=" + h3 + "\n")
	}
	if h4 := stringVal(s.H4); h4 != "" && h4 != "0" {
		b.WriteString("h4=" + h4 + "\n")
	}

	for _, peer := range s.Peers {
		pubHex, err := decodeKeyToHex(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("invalid peer public key: %w", err)
		}
		b.WriteString("public_key=" + pubHex + "\n")

		if peer.PreSharedKey != "" {
			pskHex, err := decodeKeyToHex(peer.PreSharedKey)
			if err == nil && pskHex != "" {
				b.WriteString("preshared_key=" + pskHex + "\n")
			}
		}

		if peer.Endpoint != "" {
			b.WriteString("endpoint=" + peer.Endpoint + "\n")
		}

		allowed := peer.AllowedIPs
		if len(allowed) == 0 {
			allowed = []string{"0.0.0.0/0", "::/0"}
		}
		for _, ip := range allowed {
			b.WriteString("allowed_ip=" + ip + "\n")
		}

		if ka := stringVal(peer.KeepAlive); ka != "" && ka != "0" {
			b.WriteString("persistent_keepalive_interval=" + ka + "\n")
		}
	}

	return b.String(), nil
}

// AmneziaWgRunner manages the lifecycle of an AmneziaWG netstack tunnel with a local SOCKS5 listener.
type AmneziaWgRunner struct {
	mu        sync.Mutex
	tun       tun.Device
	dev       *device.Device
	tnet      *netstack.Net
	listener  net.Listener
	socksPort int
	running   bool
	cancel    context.CancelFunc
}

var (
	awgGlobalMu     sync.Mutex
	activeAwgRunner *AmneziaWgRunner
)

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
		_ = activeAwgRunner.Stop()
		activeAwgRunner = nil
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

// StopAmneziaWg stops the currently active AmneziaWG runner.
func StopAmneziaWg() error {
	awgGlobalMu.Lock()
	defer awgGlobalMu.Unlock()

	if activeAwgRunner == nil {
		return nil
	}
	err := activeAwgRunner.Stop()
	activeAwgRunner = nil
	return err
}

// IsAmneziaWgRunning reports whether AmneziaWG is currently active.
func IsAmneziaWgRunning() bool {
	awgGlobalMu.Lock()
	defer awgGlobalMu.Unlock()
	return activeAwgRunner != nil && activeAwgRunner.running
}

// NewAmneziaWgRunner builds an AmneziaWgRunner instance from parsed settings.
func NewAmneziaWgRunner(settings *AmneziaWgSettings, socksPort int) (*AmneziaWgRunner, error) {
	if socksPort <= 0 {
		socksPort = 10809
	}

	var localAddrs []netip.Addr
	switch addrVal := settings.Address.(type) {
	case string:
		if prefix, err := netip.ParsePrefix(addrVal); err == nil {
			localAddrs = append(localAddrs, prefix.Addr())
		} else if addr, err := netip.ParseAddr(addrVal); err == nil {
			localAddrs = append(localAddrs, addr)
		}
	case []any:
		for _, a := range addrVal {
			if str, ok := a.(string); ok {
				if prefix, err := netip.ParsePrefix(str); err == nil {
					localAddrs = append(localAddrs, prefix.Addr())
				} else if addr, err := netip.ParseAddr(str); err == nil {
					localAddrs = append(localAddrs, addr)
				}
			}
		}
	}
	if len(localAddrs) == 0 {
		localAddrs = []netip.Addr{netip.MustParseAddr("10.8.0.2")}
	}

	mtu := settings.MTU
	if mtu <= 0 {
		mtu = 1420
	}

	dnsAddrs := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}

	tunDev, tnet, err := netstack.CreateNetTUN(localAddrs, dnsAddrs, mtu)
	if err != nil {
		return nil, fmt.Errorf("create netstack tun: %w", err)
	}

	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {},
		Errorf:   func(format string, args ...any) {},
	}

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	ipcString, err := settings.BuildIpcConfig()
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("build ipc config: %w", err)
	}

	if err := dev.IpcSet(ipcString); err != nil {
		dev.Close()
		return nil, fmt.Errorf("device IpcSet failed: %w", err)
	}

	return &AmneziaWgRunner{
		tun:       tunDev,
		dev:       dev,
		tnet:      tnet,
		socksPort: socksPort,
	}, nil
}

// Start brings up the AmneziaWG device and listens on the local SOCKS5 port.
func (r *AmneziaWgRunner) Start() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return nil
	}

	if err := r.dev.Up(); err != nil {
		return fmt.Errorf("device Up failed: %w", err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", r.socksPort))
	if err != nil {
		return fmt.Errorf("listen on socks port %d: %w", r.socksPort, err)
	}
	r.listener = ln
	r.socksPort = ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.running = true

	go r.serveSocks(ctx, ln)
	return nil
}

// Stop terminates the SOCKS5 server and shuts down the AmneziaWG device.
func (r *AmneziaWgRunner) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}
	r.running = false

	if r.cancel != nil {
		r.cancel()
	}
	if r.listener != nil {
		_ = r.listener.Close()
		r.listener = nil
	}
	if r.dev != nil {
		r.dev.Close()
		r.dev = nil
	} else if r.tun != nil {
		_ = r.tun.Close()
	}
	r.tun = nil
	return nil
}

// serveSocks accepts inbound SOCKS5 connections from local applications or Xray.
func (r *AmneziaWgRunner) serveSocks(ctx context.Context, ln net.Listener) {
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(20 * time.Millisecond)
				continue
			}
		}
		go r.handleSocksConn(ctx, clientConn)
	}
}

// handleSocksConn handles a single SOCKS5 TCP client connection.
func (r *AmneziaWgRunner) handleSocksConn(ctx context.Context, c net.Conn) {
	defer c.Close()

	// 1. Negotiation
	var header [2]byte
	if _, err := io.ReadFull(c, header[:]); err != nil || header[0] != 0x05 {
		return
	}
	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	// Reply: No authentication required
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Request
	var reqHeader [4]byte
	if _, err := io.ReadFull(c, reqHeader[:]); err != nil {
		return
	}
	if reqHeader[0] != 0x05 || reqHeader[1] != 0x01 { // Only CONNECT command is forwarded to TCP
		_ = sendSocksReply(c, 0x07) // Command not supported
		return
	}

	var destAddr string
	switch reqHeader[3] {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return
		}
		destAddr = net.IP(ip[:]).String()
	case 0x03: // Domain name
		var lenByte [1]byte
		if _, err := io.ReadFull(c, lenByte[:]); err != nil {
			return
		}
		domainBytes := make([]byte, int(lenByte[0]))
		if _, err := io.ReadFull(c, domainBytes); err != nil {
			return
		}
		destAddr = string(domainBytes)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return
		}
		destAddr = net.IP(ip[:]).String()
	default:
		_ = sendSocksReply(c, 0x08) // Address type not supported
		return
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(c, portBytes[:]); err != nil {
		return
	}
	destPort := binary.BigEndian.Uint16(portBytes[:])

	// 3. Dial target via AmneziaWG netstack
	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	defer dialCancel()

	var tcpAddr *net.TCPAddr
	if ip := net.ParseIP(destAddr); ip != nil {
		tcpAddr = &net.TCPAddr{IP: ip, Port: int(destPort)}
	} else {
		addrs, err := r.tnet.LookupHost(destAddr)
		if err != nil || len(addrs) == 0 {
			// Fallback local lookup if netstack lookup fails
			ips, err2 := net.LookupHost(destAddr)
			if err2 != nil || len(ips) == 0 {
				_ = sendSocksReply(c, 0x04) // Host unreachable
				return
			}
			addrs = ips
		}
		ip := net.ParseIP(addrs[0])
		if ip == nil {
			_ = sendSocksReply(c, 0x04)
			return
		}
		tcpAddr = &net.TCPAddr{IP: ip, Port: int(destPort)}
	}

	remoteConn, err := r.tnet.DialContextTCP(dialCtx, tcpAddr)
	if err != nil {
		_ = sendSocksReply(c, 0x05) // Connection refused
		return
	}
	defer remoteConn.Close()

	// 4. Send SOCKS Success response
	if err := sendSocksReply(c, 0x00); err != nil {
		return
	}

	// 5. Bidirectional stream copy
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remoteConn, c)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, remoteConn)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

func sendSocksReply(c net.Conn, rep byte) error {
	reply := []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err := c.Write(reply)
	return err
}

// RewriteWireguardOutboundToSocks rewrites wireguard/amneziawg outbounds in Xray JSON to point to a local SOCKS5 listener.
func RewriteWireguardOutboundToSocks(rawJSON string, socksPort int) string {
	var generic map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &generic); err != nil {
		return rawJSON
	}
	outbounds, ok := generic["outbounds"].([]any)
	if !ok {
		return rawJSON
	}
	modified := false
	for i, ob := range outbounds {
		obMap, ok := ob.(map[string]any)
		if !ok {
			continue
		}
		proto, _ := obMap["protocol"].(string)
		if proto == "wireguard" || proto == "amneziawg" {
			tag, _ := obMap["tag"].(string)
			if tag == "" {
				tag = "proxy"
			}
			outbounds[i] = map[string]any{
				"tag":      tag,
				"protocol": "socks",
				"settings": map[string]any{
					"servers": []any{
						map[string]any{
							"address": "127.0.0.1",
							"port":    socksPort,
						},
					},
				},
			}
			modified = true
		}
	}
	if !modified {
		return rawJSON
	}
	generic["outbounds"] = outbounds
	rewritten, err := json.Marshal(generic)
	if err != nil {
		return rawJSON
	}
	return string(rewritten)
}
