// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package nmtun brings up SKIPI's TUN interface through NetworkManager so the application itself
// never needs network privileges. NetworkManager (a root daemon) creates a tun device owned by
// the calling user and configures its addresses and routes; the application then attaches to the
// device and receives packets. When the application's D-Bus connection closes, for any reason,
// NetworkManager removes the interface and everything it configured.
package nmtun

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"

	"github.com/godbus/dbus/v5"
)

const (
	minMTU = 1280
	maxMTU = 65535
)

var (
	interfaceNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,14}$`)
	userNamePattern      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
)

// Plan is the interface a host asks for. It is sent by the application as JSON.
type Plan struct {
	Name      string   `json:"name"`
	MTU       int      `json:"mtu"`
	Addresses []string `json:"addresses"`
	Routes    []string `json:"routes"`
}

// ParsePlan decodes the host's JSON.
func ParsePlan(text string) (Plan, error) {
	var plan Plan
	if err := json.Unmarshal([]byte(text), &plan); err != nil {
		return Plan{}, fmt.Errorf("invalid TUN plan: %w", err)
	}
	return plan, nil
}

// CheckInterfaceName reports whether name is an acceptable TUN interface name.
func CheckInterfaceName(name string) error {
	if !interfaceNamePattern.MatchString(name) {
		return fmt.Errorf("invalid interface name %q", name)
	}
	return nil
}

// Settings converts the plan into NetworkManager connection settings for a tun device owned by
// uid. Only the owner may use the connection.
func (p Plan) Settings(uid int, user string) (map[string]map[string]dbus.Variant, error) {
	if err := CheckInterfaceName(p.Name); err != nil {
		return nil, err
	}
	if p.MTU < minMTU || p.MTU > maxMTU {
		return nil, fmt.Errorf("MTU %d is outside %d..%d", p.MTU, minMTU, maxMTU)
	}
	if !userNamePattern.MatchString(user) {
		return nil, fmt.Errorf("invalid user name %q", user)
	}

	var v4Address, v6Address []map[string]dbus.Variant
	for _, text := range p.Addresses {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", text, err)
		}
		entry := map[string]dbus.Variant{
			"address": dbus.MakeVariant(prefix.Addr().String()),
			"prefix":  dbus.MakeVariant(uint32(prefix.Bits())),
		}
		if prefix.Addr().Is4() {
			v4Address = append(v4Address, entry)
		} else {
			v6Address = append(v6Address, entry)
		}
	}
	if len(v4Address) == 0 {
		return nil, errors.New("an IPv4 address is required")
	}
	if len(v4Address) > 1 || len(v6Address) > 1 {
		return nil, errors.New("at most one address per family is supported")
	}

	var v4Routes, v6Routes []map[string]dbus.Variant
	for _, text := range p.Routes {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return nil, fmt.Errorf("invalid route %q: %w", text, err)
		}
		prefix = prefix.Masked()
		entry := map[string]dbus.Variant{
			"dest":   dbus.MakeVariant(prefix.Addr().String()),
			"prefix": dbus.MakeVariant(uint32(prefix.Bits())),
		}
		if prefix.Addr().Is4() {
			v4Routes = append(v4Routes, entry)
		} else {
			v6Routes = append(v6Routes, entry)
		}
	}
	if len(v6Routes) > 0 && len(v6Address) == 0 {
		return nil, errors.New("IPv6 routes require an IPv6 address")
	}

	ipv4 := map[string]dbus.Variant{
		"method":        dbus.MakeVariant("manual"),
		"address-data":  dbus.MakeVariant(v4Address),
		"never-default": dbus.MakeVariant(true),
	}
	if len(v4Routes) > 0 {
		ipv4["route-data"] = dbus.MakeVariant(v4Routes)
	}
	ipv6 := map[string]dbus.Variant{"method": dbus.MakeVariant("ignore")}
	if len(v6Address) > 0 {
		ipv6 = map[string]dbus.Variant{
			"method":        dbus.MakeVariant("manual"),
			"address-data":  dbus.MakeVariant(v6Address),
			"never-default": dbus.MakeVariant(true),
		}
		if len(v6Routes) > 0 {
			ipv6["route-data"] = dbus.MakeVariant(v6Routes)
		}
	}

	return map[string]map[string]dbus.Variant{
		"connection": {
			"id":             dbus.MakeVariant("SKIPI TUN"),
			"type":           dbus.MakeVariant("tun"),
			"interface-name": dbus.MakeVariant(p.Name),
			"autoconnect":    dbus.MakeVariant(false),
			"permissions":    dbus.MakeVariant([]string{"user:" + user + ":"}),
		},
		"tun": {
			"mode":  dbus.MakeVariant(uint32(1)),
			"owner": dbus.MakeVariant(fmt.Sprint(uid)),
			"pi":    dbus.MakeVariant(false),
		},
		"802-3-ethernet": {"mtu": dbus.MakeVariant(uint32(p.MTU))},
		"ipv4":           ipv4,
		"ipv6":           ipv6,
	}, nil
}
