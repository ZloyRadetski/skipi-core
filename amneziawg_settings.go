// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ZloyRadetski/skipi-core/internal/amneziawg"
)

// Methods of the bound AmneziaWgSettings. They live in the root package because Go methods must
// sit next to their type; the value parsing and endpoint resolution they use is in internal/amneziawg.

const (
	amneziaWgMaxJunkCount               = 128
	amneziaWgHeaderProtectionMinPadding = 12
	amneziaWgMaxJunkOrPaddingSize       = 1280
)

// version31Flags lists the AmneziaWG 3.1 boolean settings with their JSON and UAPI names.
func (s *AmneziaWgSettings) version31Flags() []struct {
	name, uapi string
	value      any
} {
	return []struct {
		name, uapi string
		value      any
	}{
		{"RandomTrailers", "random_trailers", s.RandomTrailers},
		{"DisableCookies", "disable_cookies", s.DisableCookies},
	}
}

// version3Ranges lists the AmneziaWG 3.0 range settings with their JSON and UAPI names.
func (s *AmneziaWgSettings) version3Ranges() []struct {
	name, uapi string
	value      any
} {
	return []struct {
		name, uapi string
		value      any
	}{
		{"ContentPaddingAddition", "content_padding_addition", s.ContentPaddingAddition},
		{"RekeyAfterTime", "rekey_after_time", s.RekeyAfterTime},
		{"RekeyTimeout", "rekey_timeout", s.RekeyTimeout},
		{"RejectAfterTime", "reject_after_time", s.RejectAfterTime},
		{"KeepaliveTimeout", "keepalive_timeout", s.KeepaliveTimeout},
		{"MaxHandshakeAttempts", "max_handshake_attempts", s.MaxHandshakeAttempts},
	}
}

// HasAmneziaParams returns true if any AmneziaWG obfuscation parameter is configured.
func (s *AmneziaWgSettings) HasAmneziaParams() bool {
	if s.Jc > 0 || s.Jmin > 0 || s.Jmax > 0 || s.S1 > 0 || s.S2 > 0 || s.S3 > 0 || s.S4 > 0 {
		return true
	}
	if amneziawg.StringVal(s.H1) != "" && amneziawg.StringVal(s.H1) != "0" {
		return true
	}
	if amneziawg.StringVal(s.H2) != "" && amneziawg.StringVal(s.H2) != "0" {
		return true
	}
	if amneziawg.StringVal(s.H3) != "" && amneziawg.StringVal(s.H3) != "0" {
		return true
	}
	if amneziawg.StringVal(s.H4) != "" && amneziawg.StringVal(s.H4) != "0" {
		return true
	}
	for _, spec := range []string{s.I1, s.I2, s.I3, s.I4, s.I5} {
		if strings.TrimSpace(spec) != "" {
			return true
		}
	}
	if strings.TrimSpace(s.HeaderProtectionKey) != "" {
		return true
	}
	for _, f := range s.version31Flags() {
		if _, set, _ := amneziawg.ParseFlag(f.value); set {
			return true
		}
	}
	for _, r := range s.version3Ranges() {
		if _, set := amneziawg.RangeSet(r.value); set {
			return true
		}
	}
	return false
}

// validateNativeRunnerCompatibility rejects values which the upstream AWG
// runtime cannot safely recover from. In particular, jc above 128 has caused
// an Android Go-runtime abort rather than a normal configuration error.
func (s *AmneziaWgSettings) validateNativeRunnerCompatibility() error {
	if s == nil {
		return errors.New("AmneziaWG settings are required")
	}
	if s.Jc < 0 || s.Jc > amneziaWgMaxJunkCount {
		return fmt.Errorf("AmneziaWG jc must be between 0 and %d", amneziaWgMaxJunkCount)
	}
	for _, value := range []struct {
		name  string
		value int
	}{
		{"jmin", s.Jmin},
		{"jmax", s.Jmax},
		{"s1", s.S1},
		{"s2", s.S2},
		{"s3", s.S3},
		{"s4", s.S4},
	} {
		if value.value < 0 || value.value > amneziaWgMaxJunkOrPaddingSize {
			return fmt.Errorf("AmneziaWG %s must be between 0 and %d", value.name, amneziaWgMaxJunkOrPaddingSize)
		}
	}
	if s.Jmin > 0 && s.Jmax > 0 && s.Jmin > s.Jmax {
		return errors.New("AmneziaWG jmin must not be greater than jmax")
	}
	for _, value := range []struct {
		name  string
		value any
	}{
		{"H1", s.H1},
		{"H2", s.H2},
		{"H3", s.H3},
		{"H4", s.H4},
	} {
		if err := amneziawg.ValidateHeaderRange(value.name, amneziawg.StringVal(value.value)); err != nil {
			return err
		}
	}
	for _, value := range []struct {
		name  string
		value string
	}{
		{"I1", s.I1},
		{"I2", s.I2},
		{"I3", s.I3},
		{"I4", s.I4},
		{"I5", s.I5},
	} {
		if err := amneziawg.ValidateObfuscationChain(value.name, value.value); err != nil {
			return err
		}
	}
	if key := strings.TrimSpace(s.HeaderProtectionKey); key != "" {
		if _, err := amneziawg.DecodeKeyToHex(key); err != nil {
			return fmt.Errorf("AmneziaWG HeaderProtectionKey is invalid: %w", err)
		}
		// The runner encrypts the header with a 12-byte nonce carried in the S1..S4 padding.
		for _, padding := range []struct {
			name  string
			value int
		}{{"s1", s.S1}, {"s2", s.S2}, {"s3", s.S3}, {"s4", s.S4}} {
			if padding.value < amneziaWgHeaderProtectionMinPadding {
				return fmt.Errorf("AmneziaWG %s must be at least %d to use HeaderProtectionKey", padding.name, amneziaWgHeaderProtectionMinPadding)
			}
		}
	}
	for _, r := range s.version3Ranges() {
		if text, set := amneziawg.RangeSet(r.value); set {
			if err := amneziawg.ValidateU16Range(r.name, text); err != nil {
				return err
			}
		}
	}
	for _, f := range s.version31Flags() {
		if _, _, err := amneziawg.ParseFlag(f.value); err != nil {
			return fmt.Errorf("AmneziaWG %s %w", f.name, err)
		}
	}
	if len(s.Peers) == 0 {
		return errors.New("AmneziaWG requires a peer")
	}
	for index, peer := range s.Peers {
		if peer == nil {
			return fmt.Errorf("AmneziaWG peer %d is missing", index)
		}
		if text, set := amneziawg.RangeSet(peer.KeepAlive); set {
			if err := amneziawg.ValidateU16Range("PersistentKeepalive", text); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *AmneziaWgSettings) resolvePeerEndpoints(dnsServers []netip.Addr) error {
	for index, peer := range s.Peers {
		if peer == nil {
			return fmt.Errorf("AmneziaWG peer %d is missing", index)
		}
		endpoint, err := amneziawg.ResolveEndpoint(peer.Endpoint, func(ctx context.Context, host string) ([]netip.Addr, error) {
			return amneziawg.LookupHostWithFallback(
				ctx,
				host,
				func(systemCtx context.Context, lookupHost string) ([]netip.Addr, error) {
					return net.DefaultResolver.LookupNetIP(systemCtx, "ip", lookupHost)
				},
				func(configuredDnsCtx context.Context, lookupHost string) ([]netip.Addr, error) {
					return amneziawg.LookupHostWithConfiguredDNS(configuredDnsCtx, lookupHost, dnsServers)
				},
			)
		})
		if err != nil {
			return fmt.Errorf("resolve AmneziaWG peer %d endpoint: %w", index, err)
		}
		peer.Endpoint = endpoint
	}
	return nil
}

// uapiBuilder collects UAPI lines. The protocol is line based, so a value carrying a line break
// (or a NUL) would add settings of its own; every write must be exactly one line.
type uapiBuilder struct {
	strings.Builder
	err error
}

func (u *uapiBuilder) WriteString(line string) (int, error) {
	body, ok := strings.CutSuffix(line, "\n")
	if !ok || strings.ContainsAny(body, "\r\n\x00") {
		if u.err == nil {
			key, _, _ := strings.Cut(body, "=")
			u.err = fmt.Errorf("AmneziaWG setting %s has a line break or NUL in its value", key)
		}
		return 0, nil
	}
	return u.Builder.WriteString(line)
}

// BuildIpcConfig builds the AmneziaWG UAPI IPC configuration string.
func (s *AmneziaWgSettings) BuildIpcConfig() (string, error) {
	privHex, err := amneziawg.DecodeKeyToHex(s.SecretKey)
	if err != nil {
		return "", fmt.Errorf("invalid secret key: %w", err)
	}

	var b uapiBuilder
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

	if h1 := amneziawg.StringVal(s.H1); h1 != "" && h1 != "0" {
		b.WriteString("h1=" + h1 + "\n")
	}
	if h2 := amneziawg.StringVal(s.H2); h2 != "" && h2 != "0" {
		b.WriteString("h2=" + h2 + "\n")
	}
	if h3 := amneziawg.StringVal(s.H3); h3 != "" && h3 != "0" {
		b.WriteString("h3=" + h3 + "\n")
	}
	if h4 := amneziawg.StringVal(s.H4); h4 != "" && h4 != "0" {
		b.WriteString("h4=" + h4 + "\n")
	}

	for index, spec := range []string{s.I1, s.I2, s.I3, s.I4, s.I5} {
		if spec = strings.TrimSpace(spec); spec != "" {
			b.WriteString(fmt.Sprintf("i%d=%s\n", index+1, spec))
		}
	}

	if key := strings.TrimSpace(s.HeaderProtectionKey); key != "" {
		keyHex, err := amneziawg.DecodeKeyToHex(key)
		if err != nil {
			return "", fmt.Errorf("invalid header protection key: %w", err)
		}
		b.WriteString("header_protection_key=" + keyHex + "\n")
	}
	for _, r := range s.version3Ranges() {
		if text, set := amneziawg.RangeSet(r.value); set {
			b.WriteString(r.uapi + "=" + text + "\n")
		}
	}
	for _, f := range s.version31Flags() {
		value, set, err := amneziawg.ParseFlag(f.value)
		if err != nil {
			return "", fmt.Errorf("AmneziaWG %s %w", f.name, err)
		}
		if set {
			b.WriteString(f.uapi + "=" + strconv.FormatBool(value) + "\n")
		}
	}

	for _, peer := range s.Peers {
		if peer == nil {
			return "", errors.New("AmneziaWG peer is missing")
		}
		pubHex, err := amneziawg.DecodeKeyToHex(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("invalid peer public key: %w", err)
		}
		b.WriteString("public_key=" + pubHex + "\n")

		if strings.TrimSpace(peer.PreSharedKey) != "" {
			// A key that does not decode fails the start: a tunnel without it is not the one asked for.
			pskHex, err := amneziawg.DecodeKeyToHex(peer.PreSharedKey)
			if err != nil {
				return "", fmt.Errorf("invalid peer pre-shared key: %w", err)
			}
			b.WriteString("preshared_key=" + pskHex + "\n")
		}

		if peer.Endpoint != "" {
			b.WriteString("endpoint=" + peer.Endpoint + "\n")
		}

		allowed := peer.AllowedIPs
		if len(allowed) == 0 {
			allowed = []string{"0.0.0.0/0", "::/0"}
		}
		for _, ip := range allowed {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(ip))
			if err != nil {
				return "", fmt.Errorf("invalid peer allowed IP %q: %w", ip, err)
			}
			b.WriteString("allowed_ip=" + prefix.String() + "\n")
		}

		if ka, set := amneziawg.RangeSet(peer.KeepAlive); set {
			b.WriteString("persistent_keepalive_interval=" + ka + "\n")
		}
	}

	if b.err != nil {
		return "", b.err
	}
	return b.String(), nil
}

// netstackDNSAddresses validates the resolvers used for names requested over
// the native SOCKS bridge. A public fallback here would silently bypass the
// application's DNS policy, so callers must pass at least one raw IP address.
func (s *AmneziaWgSettings) netstackDNSAddresses() ([]netip.Addr, error) {
	addresses := make([]netip.Addr, 0, len(s.DNSServers))
	seen := make(map[netip.Addr]struct{}, len(s.DNSServers))
	for _, raw := range s.DNSServers {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		address, err := netip.ParseAddr(value)
		if err != nil || !address.IsValid() || address.IsUnspecified() {
			return nil, fmt.Errorf("invalid AmneziaWG DNS server %q", raw)
		}
		address = address.Unmap()
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	if len(addresses) == 0 {
		return nil, errors.New("AmneziaWG dnsServers is required")
	}
	return addresses, nil
}
