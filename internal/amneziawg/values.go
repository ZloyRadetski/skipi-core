// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package amneziawg holds the parts of the AmneziaWG integration that do not depend on the
// bound types: setting-value parsing and validation, peer endpoint resolution, the SOCKS5
// wire helpers and the Xray outbound rewrite. The bound types themselves (AmneziaWgSettings,
// AmneziaWgRunner, ...) stay in the root package because gomobile only binds types defined there.
package amneziawg

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// maxObfuscationChainBytes bounds one I1..I5 chain specification.
const maxObfuscationChainBytes = 4096

// ParseFlag reads a 3.1 flag. set is false for an absent or empty value; err for anything that is
// not true/false, on/off or 1/0.
func ParseFlag(v any) (value, set bool, err error) {
	switch val := v.(type) {
	case nil:
		return false, false, nil
	case bool:
		return val, true, nil
	}
	switch strings.ToLower(StringVal(v)) {
	case "":
		return false, false, nil
	case "on", "true", "1":
		return true, true, nil
	case "off", "false", "0":
		return false, true, nil
	}
	return false, true, fmt.Errorf("must be on/off, true/false or 1/0, got %q", StringVal(v))
}

// RangeSet reports whether an AmneziaWG 3.0 range value is configured ("", "0" and "off" are not).
func RangeSet(v any) (string, bool) {
	text := StringVal(v)
	return text, text != "" && text != "0" && !strings.EqualFold(text, "off")
}

// ValidateU16Range accepts "N" or "N-M" with 0 <= N <= M <= 65535.
func ValidateU16Range(name, value string) error {
	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return fmt.Errorf("AmneziaWG %s must be a number or a range", name)
	}
	var bounds []uint64
	for _, part := range parts {
		if part == "" || strings.TrimSpace(part) != part || part[0] == '+' {
			return fmt.Errorf("AmneziaWG %s must be a number or a range", name)
		}
		n, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			return fmt.Errorf("AmneziaWG %s must be between 0 and 65535: %w", name, err)
		}
		bounds = append(bounds, n)
	}
	if bounds[0] > bounds[len(bounds)-1] {
		return fmt.Errorf("AmneziaWG %s range is descending", name)
	}
	return nil
}

// StringVal renders a JSON-decoded setting value as trimmed text; nil is empty.
func StringVal(v any) string {
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

// ValidateHeaderRange accepts "" or "0" (unset), a uint32, or a uint32 range "N-M".
func ValidateHeaderRange(name, value string) error {
	if value == "" || value == "0" {
		return nil
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("AmneziaWG %s must not contain surrounding whitespace", name)
	}
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 || parts[0] == "" || (len(parts) == 2 && parts[1] == "") {
		return fmt.Errorf("AmneziaWG %s must be a uint32 or uint32 range", name)
	}
	lower, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return fmt.Errorf("AmneziaWG %s has an invalid lower bound: %w", name, err)
	}
	upper := lower
	if len(parts) == 2 {
		upper, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return fmt.Errorf("AmneziaWG %s has an invalid upper bound: %w", name, err)
		}
	}
	if upper < lower {
		return fmt.Errorf("AmneziaWG %s range is descending", name)
	}
	return nil
}

// ValidateObfuscationChain checks an I1..I5 chain made of <b>, <r>, <rc>, <rd>, <dz>, <t>, <d>, <ds> tags.
func ValidateObfuscationChain(name, spec string) error {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	if len(spec) > maxObfuscationChainBytes {
		return fmt.Errorf("AmneziaWG %s chain is too large", name)
	}
	remaining := spec
	totalFixedBytes := 0
	for remaining != "" {
		if !strings.HasPrefix(remaining, "<") {
			return fmt.Errorf("AmneziaWG %s chain has text outside a tag", name)
		}
		end := strings.IndexByte(remaining, '>')
		if end < 0 {
			return fmt.Errorf("AmneziaWG %s chain has an unterminated tag", name)
		}
		parts := strings.Fields(remaining[1:end])
		if len(parts) == 0 || len(parts) > 2 {
			return fmt.Errorf("AmneziaWG %s chain has an invalid tag", name)
		}
		kind := parts[0]
		argument := ""
		if len(parts) == 2 {
			argument = parts[1]
		}
		switch kind {
		case "b":
			bytesText := strings.TrimPrefix(argument, "0x")
			if argument == "" || bytesText == "" || len(bytesText)%2 != 0 {
				return fmt.Errorf("AmneziaWG %s chain has an invalid byte tag", name)
			}
			if _, err := hex.DecodeString(bytesText); err != nil {
				return fmt.Errorf("AmneziaWG %s chain has an invalid byte tag: %w", name, err)
			}
			totalFixedBytes += len(bytesText) / 2
		case "r", "rc", "rd", "dz":
			length, err := strconv.ParseUint(argument, 10, 16)
			if err != nil || length > maxObfuscationChainBytes {
				return fmt.Errorf("AmneziaWG %s chain has an invalid %s length", name, kind)
			}
			totalFixedBytes += int(length)
		case "t", "d", "ds":
			if argument != "" {
				return fmt.Errorf("AmneziaWG %s chain tag <%s> must not have an argument", name, kind)
			}
		default:
			return fmt.Errorf("AmneziaWG %s chain has unsupported tag <%s>", name, kind)
		}
		if totalFixedBytes > maxObfuscationChainBytes {
			return fmt.Errorf("AmneziaWG %s chain is too large", name)
		}
		remaining = remaining[end+1:]
	}
	return nil
}

// DecodeKeyToHex normalizes a WireGuard key from Base64 or Hex to 32-byte Hex.
func DecodeKeyToHex(raw string) (string, error) {
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
