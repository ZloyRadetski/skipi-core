// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package nmtun brings up SKIPI's TUN interface through NetworkManager so the application itself
// never needs network privileges. NetworkManager (a root daemon) creates a tun device owned by
// the calling user and configures its addresses and routes; the application then attaches to the
// device and receives packets. When the application's D-Bus connection closes, for any reason,
// NetworkManager removes the interface and everything it configured.
package nmtun

import (
	"encoding/binary"
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

	// dnsPriority is NetworkManager's VPN default made negative: a negative priority excludes the DNS
	// of every connection with a higher value, so the tunnel's resolver is the only one in use.
	dnsPriority = int32(-50)
)

// dnsAllDomains is the routing domain that matches every name, so systemd-resolved sends all
// queries to the tunnel's link instead of the physical one.
var dnsAllDomains = []string{"~."}

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
	// DNS lists the resolvers the system uses while the interface is up. Their queries enter the
	// tunnel, where Core answers them; without them the system keeps resolving outside the tunnel.
	DNS []string `json:"dns,omitempty"`
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

	// NetworkManager's ipv4.dns is "au": each address is the uint32 whose in-memory bytes are the
	// address in network order. ipv6.dns is "aay": the raw 16 bytes.
	var v4DNS []uint32
	var v6DNS [][]byte
	for _, text := range p.DNS {
		addr, err := netip.ParseAddr(text)
		if err != nil || addr.Zone() != "" {
			return nil, fmt.Errorf("invalid DNS server %q", text)
		}
		if addr.Is4() {
			bytes := addr.As4()
			v4DNS = append(v4DNS, binary.NativeEndian.Uint32(bytes[:]))
		} else {
			bytes := addr.As16()
			v6DNS = append(v6DNS, bytes[:])
		}
	}
	if len(v6DNS) > 0 && len(v6Address) == 0 {
		return nil, errors.New("an IPv6 DNS server requires an IPv6 address")
	}

	ipv4 := map[string]dbus.Variant{
		"method":        dbus.MakeVariant("manual"),
		"address-data":  dbus.MakeVariant(v4Address),
		"never-default": dbus.MakeVariant(true),
	}
	if len(v4Routes) > 0 {
		ipv4["route-data"] = dbus.MakeVariant(v4Routes)
	}
	if len(p.DNS) > 0 {
		// The routing domain and the priority belong to the connection as a whole, so IPv4 carries
		// them even when every server is IPv6.
		ipv4["dns-search"] = dbus.MakeVariant(dnsAllDomains)
		ipv4["dns-priority"] = dbus.MakeVariant(dnsPriority)
	}
	if len(v4DNS) > 0 {
		ipv4["dns"] = dbus.MakeVariant(v4DNS)
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
		if len(p.DNS) > 0 {
			ipv6["dns-search"] = dbus.MakeVariant(dnsAllDomains)
			ipv6["dns-priority"] = dbus.MakeVariant(dnsPriority)
		}
		if len(v6DNS) > 0 {
			ipv6["dns"] = dbus.MakeVariant(v6DNS)
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
