// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package desktopbridge

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ZloyRadetski/skipi-core/desktop/sysproxy"
)

type systemProxyConfig struct {
	Directory string `json:"directory"`
}

// SystemProxy runs one operation of the operating system's proxy settings, which Core owns on the
// desktop: the host asks, Core snapshots the user's settings, points the system at the local endpoints
// and gives the user's values back, also after a crash. The arguments and results are JSON so the C ABI
// stays one function:
//
//	configure   {"directory": "..."}                            -> {}
//	supported                                                    -> {"supported": bool}
//	acquire     {"host": "127.0.0.1", "httpPort": n, "socksPort": n} -> {"action": ...}
//	release, recover                                            -> {"action": ...}
//	repairStale                                                  -> {"changed": bool}
//	forceClear                                                   -> {}
//
// configure comes first; it names the directory that keeps the lease of an interrupted session.
func (r *Runtime) SystemProxy(op, arguments string) (string, error) {
	if op == "configure" {
		var config systemProxyConfig
		if err := decodeArguments(arguments, &config); err != nil {
			return "", err
		}
		if config.Directory == "" {
			return "", errors.New("the system proxy directory must not be blank")
		}
		factory := r.newSystemProxy
		if factory == nil {
			factory = sysproxy.NewDefault
		}
		r.mu.Lock()
		r.systemProxy = factory(config.Directory)
		r.mu.Unlock()
		return "{}", nil
	}

	r.mu.Lock()
	manager := r.systemProxy
	r.mu.Unlock()
	if manager == nil {
		return "", errors.New("the system proxy is not configured")
	}

	switch op {
	case "supported":
		return marshal(struct {
			Supported bool `json:"supported"`
		}{manager.Supported()})
	case "acquire":
		var endpoints sysproxy.Endpoints
		if err := decodeArguments(arguments, &endpoints); err != nil {
			return "", err
		}
		return resultOf(manager.Acquire(endpoints))
	case "release":
		return resultOf(manager.Release())
	case "recover":
		return resultOf(manager.Recover())
	case "repairStale":
		changed, err := manager.RepairStale()
		if err != nil {
			return "", err
		}
		return marshal(struct {
			Changed bool `json:"changed"`
		}{changed})
	case "forceClear":
		if err := manager.ForceClear(); err != nil {
			return "", err
		}
		return "{}", nil
	}
	return "", fmt.Errorf("unknown system proxy operation %q", op)
}

func resultOf(result sysproxy.Result, err error) (string, error) {
	if err != nil {
		return "", err
	}
	return marshal(result)
}

func marshal(value any) (string, error) {
	data, err := json.Marshal(value)
	return string(data), err
}

func decodeArguments(arguments string, into any) error {
	if arguments == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(arguments), into); err != nil {
		return fmt.Errorf("invalid system proxy arguments: %w", err)
	}
	return nil
}
