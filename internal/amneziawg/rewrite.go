// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package amneziawg

import "encoding/json"

// RewriteOutboundToSocks rewrites wireguard/amneziawg outbounds in Xray JSON to point to a local SOCKS5 listener.
func RewriteOutboundToSocks(rawJSON string, socksPort int) string {
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
