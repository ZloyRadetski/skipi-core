// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
)

// secureAwgBridge gives a session's AmneziaWG SOCKS listener credentials when the app did not
// choose any: random ones go into the runner config and into every Xray socks outbound that
// points at 127.0.0.1:port, so only this session's Xray can use the tunnel's exit. Credentials the
// app chose itself are kept, and both configs are then returned unchanged. Numbers keep their
// exact text.
func secureAwgBridge(xrayJSON, awgJSON string, port int) (string, string, error) {
	awg, err := decodeJSONObject(awgJSON)
	if err != nil {
		return "", "", errors.New("session plan: amneziaWg.config is not a JSON object")
	}
	settings := awgSettingsObject(awg)
	if settings == nil {
		return xrayJSON, awgJSON, nil // the runner reports what is wrong with it
	}
	if user, _ := settings["socksUser"].(string); user != "" {
		return xrayJSON, awgJSON, nil
	}
	xray, err := decodeJSONObject(xrayJSON)
	if err != nil {
		return "", "", errors.New("session plan: xrayConfig is not a JSON object")
	}

	user, pass := "skipi-"+randomHex(4), randomHex(16)
	settings["socksUser"] = user
	settings["socksPass"] = pass
	outbounds, _ := xray["outbounds"].([]any)
	for _, ob := range outbounds {
		o, _ := ob.(map[string]any)
		if o == nil || o["protocol"] != "socks" {
			continue
		}
		s, _ := o["settings"].(map[string]any)
		servers, _ := s["servers"].([]any)
		for _, sv := range servers {
			server, _ := sv.(map[string]any)
			if server == nil || !isLoopbackHost(server["address"]) || !samePort(server["port"], port) {
				continue
			}
			server["users"] = []any{map[string]any{"user": user, "pass": pass, "level": 0}}
		}
	}

	newAwg, err := encodeJSON(awg)
	if err != nil {
		return "", "", err
	}
	newXray, err := encodeJSON(xray)
	if err != nil {
		return "", "", err
	}
	return newXray, newAwg, nil
}

// awgSettingsObject is the object holding secretKey in any shape ParseAmneziaWgSettings accepts:
// the settings themselves, an outbound, or a full Xray config.
func awgSettingsObject(root map[string]any) map[string]any {
	if _, ok := root["secretKey"]; ok {
		return root
	}
	if s, ok := root["settings"].(map[string]any); ok {
		if _, ok := s["secretKey"]; ok {
			return s
		}
	}
	outbounds, _ := root["outbounds"].([]any)
	for _, ob := range outbounds {
		o, _ := ob.(map[string]any)
		if o == nil || (o["protocol"] != "wireguard" && o["protocol"] != "amneziawg") {
			continue
		}
		if s, ok := o["settings"].(map[string]any); ok {
			if _, ok := s["secretKey"]; ok {
				return s
			}
		}
	}
	return nil
}

func isLoopbackHost(v any) bool {
	s, _ := v.(string)
	return s == "127.0.0.1" || s == "localhost" || s == "::1"
}

func samePort(v any, port int) bool {
	switch n := v.(type) {
	case json.Number:
		return n.String() == strconv.Itoa(port)
	case string:
		return n == strconv.Itoa(port)
	}
	return false
}

func decodeJSONObject(text string) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader([]byte(text)))
	d.UseNumber()
	var out map[string]any
	if err := d.Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, errors.New("not a JSON object")
	}
	return out, nil
}

func encodeJSON(v any) (string, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return "", err
	}
	return string(bytes.TrimRight(b.Bytes(), "\n")), nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
