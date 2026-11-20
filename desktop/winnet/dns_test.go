// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package winnet

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeDNS struct {
	set      [][]string // adapter then servers
	setErr   error
	flushes  int
	flushErr error
}

func (f *fakeDNS) setDNS(adapter string, servers []netip.Addr) error {
	if f.setErr != nil {
		return f.setErr
	}
	row := []string{adapter}
	for _, s := range servers {
		row = append(row, s.String())
	}
	f.set = append(f.set, row)
	return nil
}

func (f *fakeDNS) flush() error {
	f.flushes++
	return f.flushErr
}

func dnsNet(r *recorder, d *fakeDNS, background func(func())) *Net {
	return New(Config{
		Run:           r.run,
		AdapterExists: func(string) bool { return true },
		SetDNS:        d.setDNS,
		FlushDNS:      d.flush,
		Sleep:         func(time.Duration) {},
		Attempts:      1,
		Serial:        true,
		Background:    background,
	})
}

func powershellScripts(r *recorder) []string {
	var scripts []string
	for _, c := range r.commands() {
		if c[0] == "powershell.exe" {
			scripts = append(scripts, c[len(c)-1])
		}
	}
	return scripts
}

// A tunnel adapter without DNS never resolves through the tunnel, so the servers must be there when the
// connect returns: set natively they cost no process and no wait, and need no background step.
func TestNativeDnsIsSetBeforeAttachReturnsAndStartsNoPowerShell(t *testing.T) {
	r := &recorder{}
	d := &fakeDNS{}
	var background []func()
	n := dnsNet(r, d, func(f func()) { background = append(background, f) })

	if err := n.Attach(dnsPlan); err != nil {
		t.Fatal(err)
	}
	if want := [][]string{{"skipi0", "1.1.1.1", "8.8.8.8"}}; !reflect.DeepEqual(d.set, want) {
		t.Fatalf("set %v", d.set)
	}
	for _, script := range powershellScripts(r) {
		if strings.Contains(script, "Set-DnsClientServerAddress") {
			t.Fatalf("native DNS must not start the DNS script: %s", script)
		}
	}
	for _, f := range background {
		f()
	}
	for _, script := range powershellScripts(r) {
		if strings.Contains(script, "Set-DnsClientServerAddress") {
			t.Fatalf("nothing is left to do for the DNS in the background: %s", script)
		}
	}
}

func TestAFailedNativeDnsFallsBackToThePowerShellScriptInTheBackground(t *testing.T) {
	r := &recorder{}
	d := &fakeDNS{setErr: errors.New("ERROR_PROC_NOT_FOUND")}
	var background []func()
	n := dnsNet(r, d, func(f func()) { background = append(background, f) })

	if err := n.Attach(dnsPlan); err != nil {
		t.Fatalf("a DNS failure never fails the tunnel: %v", err)
	}
	for _, f := range background {
		f()
	}
	found := false
	for _, script := range powershellScripts(r) {
		found = found || strings.Contains(script, "Set-DnsClientServerAddress")
	}
	if !found {
		t.Fatal("the old script must take over")
	}
}

func TestAPlanWithoutDnsLeavesTheNativeDnsAlone(t *testing.T) {
	r := &recorder{}
	d := &fakeDNS{}
	n := dnsNet(r, d, func(f func()) { f() })
	if err := n.Attach(ipv4Plan); err != nil {
		t.Fatal(err)
	}
	if len(d.set) != 0 {
		t.Fatalf("set %v", d.set)
	}
}

func TestOnlyIpAddressesReachTheNativeDns(t *testing.T) {
	r := &recorder{}
	d := &fakeDNS{}
	n := dnsNet(r, d, func(f func()) { f() })
	plan := Plan{Name: "skipi0", Routes: ipv4Plan.Routes, DNS: []string{"1.1.1.1", "x'; calc; '", "2606:4700:4700::1111"}}

	if err := n.Attach(plan); err != nil {
		t.Fatal(err)
	}
	if want := [][]string{{"skipi0", "1.1.1.1", "2606:4700:4700::1111"}}; !reflect.DeepEqual(d.set, want) {
		t.Fatalf("set %v", d.set)
	}
}

func TestDetachFlushesTheDnsCacheNativelyBehindTheDisconnect(t *testing.T) {
	r := &recorder{}
	d := &fakeDNS{}
	var background []func()
	n := dnsNet(r, d, func(f func()) { background = append(background, f) })
	if err := n.Attach(dnsPlan); err != nil {
		t.Fatal(err)
	}
	background = nil
	r.reset()

	_ = n.Detach()
	if d.flushes != 0 {
		t.Fatal("the disconnect does not wait for the flush")
	}
	for _, f := range background {
		f()
	}
	if d.flushes != 1 {
		t.Fatalf("flushes = %d", d.flushes)
	}
	for _, script := range powershellScripts(r) {
		if strings.Contains(script, "Clear-DnsClientCache") {
			t.Fatalf("a native flush needs no PowerShell: %s", script)
		}
	}
}

func TestAFailedNativeFlushFallsBackToPowerShell(t *testing.T) {
	r := &recorder{}
	d := &fakeDNS{flushErr: errors.New("no dnsapi")}
	n := dnsNet(r, d, func(f func()) { f() })
	if err := n.Attach(dnsPlan); err != nil {
		t.Fatal(err)
	}
	r.reset()
	_ = n.Detach()

	found := false
	for _, script := range powershellScripts(r) {
		found = found || script == "Clear-DnsClientCache"
	}
	if !found {
		t.Fatalf("got %v", powershellScripts(r))
	}
}
