// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hevtun

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v2"
)

// hev runs a command from tunnel.post-up-script and tunnel.pre-down-script and writes to
// misc.log-file and misc.pid-file. Its process modes run with more rights than the app (root on
// macOS, Core's on Windows), so the config the app hands over must not be able to name any of
// those. SanitizeConfig lets through only the keys hev needs and refuses everything else.

// allowedConfigKeys are the hev keys a session may set, by section. log-file is handled apart:
// it is kept in process, where hev writes as the app, and dropped where hev has more rights.
var allowedConfigKeys = map[string]map[string]bool{
	"tunnel": {"name": true, "mtu": true, "multi-queue": true, "ipv4": true, "ipv6": true},
	"socks5": {"port": true, "address": true, "udp": true, "udp-address": true, "pipeline": true,
		"username": true, "password": true, "mark": true, "tcp-fastopen": true},
	"mapdns": {"address": true, "port": true, "network": true, "netmask": true, "cache-size": true},
	"misc": {"task-stack-size": true, "tcp-buffer-size": true, "udp-recv-buffer-size": true,
		"udp-copy-buffer-nums": true, "max-session-count": true, "connect-timeout": true,
		"tcp-read-write-timeout": true, "udp-read-write-timeout": true, "log-level": true,
		"limit-nofile": true, "log-file": true, "wintun-ring-capacity": true},
}

// SanitizeConfig checks the hev YAML against the allowed keys and returns it re-encoded. Every key
// must be known, every section a map and every value a scalar. inProcess keeps misc.log-file
// (hev then writes as the app); otherwise it is dropped, and hev logs to its output instead.
func SanitizeConfig(configYAML string, inProcess bool) (string, error) {
	var doc yaml.MapSlice
	if err := yaml.Unmarshal([]byte(configYAML), &doc); err != nil {
		return "", fmt.Errorf("hev config is not valid YAML: %w", err)
	}
	if len(doc) == 0 {
		return "", errors.New("hev config is empty")
	}
	out := make(yaml.MapSlice, 0, len(doc))
	seen := map[string]bool{}
	for _, section := range doc {
		name, ok := section.Key.(string)
		if !ok {
			return "", fmt.Errorf("hev config: key %v is not allowed", section.Key)
		}
		allowed, known := allowedConfigKeys[name]
		if !known {
			return "", fmt.Errorf("hev config: section %q is not allowed", name)
		}
		if seen[name] {
			return "", fmt.Errorf("hev config: section %q appears twice", name)
		}
		seen[name] = true
		entries, ok := section.Value.(yaml.MapSlice)
		if !ok {
			return "", fmt.Errorf("hev config: %s must be a map", name)
		}
		kept := make(yaml.MapSlice, 0, len(entries))
		seenKey := map[string]bool{}
		for _, entry := range entries {
			key, ok := entry.Key.(string)
			if !ok {
				return "", fmt.Errorf("hev config: key %s.%v is not allowed", name, entry.Key)
			}
			path := name + "." + key
			if !allowed[key] {
				return "", fmt.Errorf("hev config: key %s is not allowed", path)
			}
			if seenKey[key] {
				return "", fmt.Errorf("hev config: key %s appears twice", path)
			}
			seenKey[key] = true
			switch entry.Value.(type) {
			case string, int, int64, uint64, float64, bool:
			default:
				return "", fmt.Errorf("hev config: %s must be a single value", path)
			}
			if path == "misc.log-file" && !inProcess {
				continue
			}
			kept = append(kept, entry)
		}
		out = append(out, yaml.MapItem{Key: name, Value: kept})
	}
	b, err := yaml.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("hev config: %w", err)
	}
	return string(b), nil
}
