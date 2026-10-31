// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package nmtun

import (
	"reflect"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

func validPlan() Plan {
	return Plan{
		Name:      "skipi0",
		MTU:       1400,
		Addresses: []string{"172.19.0.1/30"},
		Routes:    []string{"0.0.0.0/1", "128.0.0.0/1"},
	}
}

func value(t *testing.T, settings map[string]map[string]dbus.Variant, section, key string) any {
	t.Helper()
	v, ok := settings[section][key]
	if !ok {
		t.Fatalf("missing %s.%s in %v", section, key, settings)
	}
	return v.Value()
}

func TestSettingsDescribeAUserOwnedTunInterface(t *testing.T) {
	settings, err := validPlan().Settings(1000, "vqsego")
	if err != nil {
		t.Fatal(err)
	}

	if got := value(t, settings, "connection", "type"); got != "tun" {
		t.Errorf("type = %v", got)
	}
	if got := value(t, settings, "connection", "interface-name"); got != "skipi0" {
		t.Errorf("interface-name = %v", got)
	}
	if got := value(t, settings, "connection", "autoconnect"); got != false {
		t.Errorf("autoconnect = %v", got)
	}
	if got := value(t, settings, "connection", "permissions"); !reflect.DeepEqual(got, []string{"user:vqsego:"}) {
		t.Errorf("permissions = %v", got)
	}
	if got := value(t, settings, "tun", "owner"); got != "1000" {
		t.Errorf("owner = %v", got)
	}
	if got := value(t, settings, "tun", "pi"); got != false {
		t.Errorf("pi = %v", got)
	}
	if got := value(t, settings, "tun", "mode"); got != uint32(1) {
		t.Errorf("mode = %v", got)
	}
	if got := value(t, settings, "802-3-ethernet", "mtu"); got != uint32(1400) {
		t.Errorf("mtu = %v", got)
	}
}

func TestSettingsSplitAddressesAndRoutesByFamily(t *testing.T) {
	plan := validPlan()
	plan.Addresses = append(plan.Addresses, "fdfe:dcba:9876::1/126")
	plan.Routes = append(plan.Routes, "::/1", "8000::/1")

	settings, err := plan.Settings(1000, "vqsego")
	if err != nil {
		t.Fatal(err)
	}

	if got := value(t, settings, "ipv4", "method"); got != "manual" {
		t.Errorf("ipv4 method = %v", got)
	}
	if got := value(t, settings, "ipv4", "never-default"); got != true {
		t.Errorf("ipv4 never-default = %v", got)
	}
	wantV4Address := []map[string]dbus.Variant{
		{"address": dbus.MakeVariant("172.19.0.1"), "prefix": dbus.MakeVariant(uint32(30))},
	}
	if got := value(t, settings, "ipv4", "address-data"); !reflect.DeepEqual(got, wantV4Address) {
		t.Errorf("ipv4 address-data = %v", got)
	}
	wantV4Routes := []map[string]dbus.Variant{
		{"dest": dbus.MakeVariant("0.0.0.0"), "prefix": dbus.MakeVariant(uint32(1))},
		{"dest": dbus.MakeVariant("128.0.0.0"), "prefix": dbus.MakeVariant(uint32(1))},
	}
	if got := value(t, settings, "ipv4", "route-data"); !reflect.DeepEqual(got, wantV4Routes) {
		t.Errorf("ipv4 route-data = %v", got)
	}
	if got := value(t, settings, "ipv6", "method"); got != "manual" {
		t.Errorf("ipv6 method = %v", got)
	}
	wantV6Routes := []map[string]dbus.Variant{
		{"dest": dbus.MakeVariant("::"), "prefix": dbus.MakeVariant(uint32(1))},
		{"dest": dbus.MakeVariant("8000::"), "prefix": dbus.MakeVariant(uint32(1))},
	}
	if got := value(t, settings, "ipv6", "route-data"); !reflect.DeepEqual(got, wantV6Routes) {
		t.Errorf("ipv6 route-data = %v", got)
	}
}

func TestSettingsIgnoreIpv6WhenThePlanHasNoIpv6Address(t *testing.T) {
	settings, err := validPlan().Settings(1000, "vqsego")
	if err != nil {
		t.Fatal(err)
	}

	if got := value(t, settings, "ipv6", "method"); got != "ignore" {
		t.Errorf("ipv6 method = %v", got)
	}
	if _, ok := settings["ipv6"]["route-data"]; ok {
		t.Error("ipv6 routes present without an address")
	}
}

func TestSettingsRejectInvalidPlans(t *testing.T) {
	cases := map[string]func(*Plan){
		"empty name":         func(p *Plan) { p.Name = "" },
		"name with slash":    func(p *Plan) { p.Name = "a/b" },
		"name too long":      func(p *Plan) { p.Name = strings.Repeat("a", 16) },
		"name with space":    func(p *Plan) { p.Name = "skipi 0" },
		"mtu too small":      func(p *Plan) { p.MTU = 1279 },
		"mtu too large":      func(p *Plan) { p.MTU = 65536 },
		"no address":         func(p *Plan) { p.Addresses = nil },
		"bad address":        func(p *Plan) { p.Addresses = []string{"172.19.0.1"} },
		"bad address prefix": func(p *Plan) { p.Addresses = []string{"172.19.0.1/33"} },
		"bad route":          func(p *Plan) { p.Routes = []string{"nope/1"} },
		"two v4 addresses":   func(p *Plan) { p.Addresses = []string{"172.19.0.1/30", "10.0.0.1/24"} },
		"v6 route no v6 ip":  func(p *Plan) { p.Routes = append(p.Routes, "::/1") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			plan := validPlan()
			mutate(&plan)
			if _, err := plan.Settings(1000, "vqsego"); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestSettingsRejectUnsafeUserNames(t *testing.T) {
	if _, err := validPlan().Settings(1000, "bad:user"); err == nil {
		t.Fatal("expected an error for a user name containing ':'")
	}
	if _, err := validPlan().Settings(1000, ""); err == nil {
		t.Fatal("expected an error for an empty user name")
	}
}

func TestParsePlanReadsTheHostJson(t *testing.T) {
	plan, err := ParsePlan(`{"name":"skipi0","mtu":1400,"addresses":["172.19.0.1/30"],"routes":["0.0.0.0/1"]}`)
	if err != nil {
		t.Fatal(err)
	}
	want := Plan{Name: "skipi0", MTU: 1400, Addresses: []string{"172.19.0.1/30"}, Routes: []string{"0.0.0.0/1"}}
	if !reflect.DeepEqual(plan, want) {
		t.Fatalf("plan = %+v", plan)
	}
	if _, err := ParsePlan("{"); err == nil {
		t.Fatal("expected a JSON error")
	}
}
