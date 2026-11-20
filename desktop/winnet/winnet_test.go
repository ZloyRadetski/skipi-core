// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package winnet

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var ipv4Plan = Plan{Name: "skipi0", Routes: []string{"0.0.0.0/1", "128.0.0.0/1"}}

var dualStackPlan = Plan{Name: "skipi0", Routes: []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}}

var dnsPlan = Plan{Name: "skipi0", Routes: []string{"0.0.0.0/1", "128.0.0.0/1"}, DNS: []string{"1.1.1.1", "8.8.8.8"}}

type recorder struct {
	mu  sync.Mutex
	ran [][]string
	// fail decides which command fails.
	fail func(command []string) error
}

func (r *recorder) run(command []string) error {
	r.mu.Lock()
	r.ran = append(r.ran, command)
	r.mu.Unlock()
	if r.fail != nil {
		return r.fail(command)
	}
	return nil
}

func (r *recorder) commands() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]string(nil), r.ran...)
}

func (r *recorder) reset() {
	r.mu.Lock()
	r.ran = nil
	r.mu.Unlock()
}

func serialNet(r *recorder, background func(func())) *Net {
	return New(Config{
		Run:           r.run,
		AdapterExists: func(string) bool { return true },
		Sleep:         func(time.Duration) {},
		Attempts:      1,
		Serial:        true,
		Background:    background,
	})
}

func joined(commands [][]string) []string {
	out := make([]string, len(commands))
	for i, c := range commands {
		out[i] = strings.Join(c, " ")
	}
	return out
}

func TestRoutesAreAddedOnTheTunnelAdapterOnLinkAndNeverPersisted(t *testing.T) {
	want := [][]string{
		{"netsh", "interface", "ipv4", "add", "route", "prefix=0.0.0.0/1", "interface=skipi0", "nexthop=0.0.0.0", "metric=1", "store=active"},
		{"netsh", "interface", "ipv4", "add", "route", "prefix=128.0.0.0/1", "interface=skipi0", "nexthop=0.0.0.0", "metric=1", "store=active"},
	}
	if got := addRouteCommands(ipv4Plan); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestIpv6RoutesUseTheIpv6ContextAndAnUnspecifiedNextHop(t *testing.T) {
	commands := addRouteCommands(dualStackPlan)
	if len(commands) != 4 {
		t.Fatalf("got %d commands", len(commands))
	}
	want := []string{"netsh", "interface", "ipv6", "add", "route", "prefix=::/1", "interface=skipi0", "nexthop=::", "metric=1", "store=active"}
	if !reflect.DeepEqual(commands[2], want) || !slices.Contains(commands[3], "prefix=8000::/1") {
		t.Fatalf("got %v", commands)
	}
}

func TestRoutesAreRemovedWithMatchingDeleteCommands(t *testing.T) {
	want := [][]string{
		{"netsh", "interface", "ipv4", "delete", "route", "prefix=0.0.0.0/1", "interface=skipi0", "store=active"},
		{"netsh", "interface", "ipv4", "delete", "route", "prefix=128.0.0.0/1", "interface=skipi0", "store=active"},
	}
	if got := deleteRouteCommands(ipv4Plan); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestAttachWaitsForTheAdapterThenAddsEveryRoute(t *testing.T) {
	r := &recorder{}
	checks := 0
	n := New(Config{
		Run:           r.run,
		AdapterExists: func(name string) bool { checks++; return name == "skipi0" && checks >= 3 },
		Sleep:         func(time.Duration) {},
		Attempts:      10,
		Serial:        true,
		Background:    func(f func()) { f() },
	})

	if err := n.Attach(ipv4Plan); err != nil {
		t.Fatal(err)
	}
	if checks != 3 {
		t.Fatalf("checks = %d", checks)
	}
	if got := r.commands()[:2]; !reflect.DeepEqual(got, addRouteCommands(ipv4Plan)) {
		t.Fatalf("the routes come first: %v", got)
	}
}

func TestAttachFailsWhenTheAdapterNeverAppears(t *testing.T) {
	r := &recorder{}
	n := New(Config{Run: r.run, AdapterExists: func(string) bool { return false }, Sleep: func(time.Duration) {}, Attempts: 4, Serial: true})

	err := n.Attach(ipv4Plan)
	if err == nil || !strings.Contains(err.Error(), "skipi0") {
		t.Fatalf("got %v", err)
	}
	if len(r.commands()) != 0 {
		t.Fatalf("nothing may run without an adapter: %v", r.commands())
	}
}

func TestAFailedRouteCommandRemovesTheRoutesAlreadyAddedAndReportsTheFailure(t *testing.T) {
	r := &recorder{fail: func(c []string) error {
		if slices.Contains(c, "prefix=128.0.0.0/1") && slices.Contains(c, "add") {
			return errors.New("netsh failed: access denied")
		}
		return nil
	}}
	n := serialNet(r, func(f func()) { f() })

	err := n.Attach(ipv4Plan)
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("got %v", err)
	}
	var deletes [][]string
	for _, c := range r.commands() {
		if slices.Contains(c, "delete") && c[0] == "netsh" {
			deletes = append(deletes, c)
		}
	}
	if !reflect.DeepEqual(deletes, deleteRouteCommands(ipv4Plan)) {
		t.Fatalf("a half routed tunnel must be undone: %v", deletes)
	}
}

func TestDetachDeletesTheRoutesAndIgnoresAlreadyMissingOnes(t *testing.T) {
	r := &recorder{}
	n := serialNet(r, func(f func()) { f() })
	if err := n.Attach(ipv4Plan); err != nil {
		t.Fatal(err)
	}
	r.reset()
	r.fail = func(c []string) error {
		if slices.Contains(c, "delete") {
			return errors.New("not found")
		}
		return nil
	}

	if err := n.Detach(); err != nil {
		t.Fatalf("a route that is already gone is not an error: %v", err)
	}
	var deletes [][]string
	for _, c := range r.commands() {
		if c[0] == "netsh" && slices.Contains(c, "delete") {
			deletes = append(deletes, c)
		}
	}
	if !reflect.DeepEqual(deletes, deleteRouteCommands(ipv4Plan)) {
		t.Fatalf("got %v", deletes)
	}
	r.reset()
	if err := n.Detach(); err != nil || len(r.commands()) != 0 {
		t.Fatalf("a second detach has nothing to delete: %v %v", err, r.commands())
	}
}

// Windows sends SSDP, LLMNR and mDNS discovery to every adapter, so a new tunnel adapter received about a
// thousand UDP flows within seconds. hev serves at most 1023 sessions at once and then fails every new
// socket, TCP included: the tunnel was up and carried no traffic.
func TestMulticastAndBroadcastAreBlockedOnlyOnTheTunnelAdapter(t *testing.T) {
	command, err := multicastBlockCommand(ipv4Plan)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(command[:4], []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-Command"}) {
		t.Fatalf("got %v", command[:4])
	}
	script := command[len(command)-1]
	for _, want := range []string{"-InterfaceAlias 'skipi0'", "-Direction Outbound", "-Action Block", "224.0.0.0/4", "255.255.255.255", "ff00::/8"} {
		if !strings.Contains(script, want) {
			t.Fatalf("%q missing from %s", want, script)
		}
	}
	if strings.Index(script, "Remove-NetFirewallRule") > strings.Index(script, "New-NetFirewallRule") {
		t.Fatal("a stale rule goes first")
	}
}

func TestAnAdapterNameThatCouldInjectIntoAScriptIsRefused(t *testing.T) {
	if _, err := multicastBlockCommand(Plan{Name: "x'; calc; '"}); err == nil {
		t.Fatal("the name goes into a script and must be a plain identifier")
	}
	if _, err := dnsCommand(Plan{Name: "x'; calc; '", DNS: []string{"1.1.1.1"}}); err == nil {
		t.Fatal("the name goes into a script and must be a plain identifier")
	}
}

func TestTheBlockRuleIsInstalledAfterTheRoutesAndRemovedOnDetach(t *testing.T) {
	r := &recorder{}
	n := serialNet(r, func(f func()) { f() })

	if err := n.Attach(ipv4Plan); err != nil {
		t.Fatal(err)
	}
	block, _ := multicastBlockCommand(ipv4Plan)
	if got, want := r.commands(), append(addRouteCommands(ipv4Plan), block); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", joined(got))
	}

	r.reset()
	_ = n.Detach()
	if got, want := r.commands(), append(deleteRouteCommands(ipv4Plan), multicastUnblockCommand()); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", joined(got))
	}
}

func TestAFailedBlockRuleDoesNotFailTheTunnel(t *testing.T) {
	r := &recorder{fail: func(c []string) error {
		if strings.Contains(c[len(c)-1], "New-NetFirewallRule") {
			return errors.New("no firewall service")
		}
		return nil
	}}
	if err := serialNet(r, func(f func()) { f() }).Attach(ipv4Plan); err != nil {
		t.Fatal(err)
	}
}

// Windows keeps the DNS servers of the physical adapter and sends queries out of the adapter that owns the
// server, so a tunnel adapter without DNS never resolves through the tunnel. The adapter gets the plan's DNS
// and the lowest interface metric, which is what the DNS client ranks by.
func TestTheTunnelAdapterIsGivenThePlansDnsAndTheLowestInterfaceMetric(t *testing.T) {
	command, err := dnsCommand(dnsPlan)
	if err != nil || command == nil {
		t.Fatalf("%v %v", command, err)
	}
	script := command[len(command)-1]
	for _, want := range []string{
		"Set-DnsClientServerAddress -InterfaceAlias 'skipi0' -ServerAddresses ('1.1.1.1','8.8.8.8')",
		"Set-NetIPInterface -InterfaceAlias 'skipi0'", "-InterfaceMetric 1", "Clear-DnsClientCache",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%q missing from %s", want, script)
		}
	}
}

func TestAPlanWithoutDnsLeavesTheAdapterDnsAlone(t *testing.T) {
	if command, err := dnsCommand(ipv4Plan); err != nil || command != nil {
		t.Fatalf("%v %v", command, err)
	}
}

func TestOnlyIpAddressesReachTheDnsScript(t *testing.T) {
	plan := Plan{Name: "skipi0", DNS: []string{"1.1.1.1", "x'; calc; '", "2606:4700:4700::1111"}}
	command, err := dnsCommand(plan)
	if err != nil {
		t.Fatal(err)
	}
	script := command[len(command)-1]
	if !strings.Contains(script, "('1.1.1.1','2606:4700:4700::1111')") || strings.Contains(script, "calc") {
		t.Fatalf("got %s", script)
	}
}

func TestDnsIsSetAfterTheRoutesAndBeforeTheBlockRule(t *testing.T) {
	r := &recorder{}
	n := serialNet(r, func(f func()) { f() })
	if err := n.Attach(dnsPlan); err != nil {
		t.Fatal(err)
	}
	dns, _ := dnsCommand(dnsPlan)
	block, _ := multicastBlockCommand(dnsPlan)
	want := append(addRouteCommands(dnsPlan), dns, block)
	if got := r.commands(); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", joined(got))
	}
}

func TestAFailedDnsCommandDoesNotFailTheTunnelAndDetachFlushesTheCache(t *testing.T) {
	r := &recorder{fail: func(c []string) error {
		if strings.Contains(c[len(c)-1], "Set-DnsClientServerAddress") {
			return errors.New("no dns")
		}
		return nil
	}}
	n := serialNet(r, func(f func()) { f() })
	if err := n.Attach(dnsPlan); err != nil {
		t.Fatal(err)
	}
	r.reset()
	_ = n.Detach()
	want := append(deleteRouteCommands(dnsPlan), multicastUnblockCommand(), dnsFlushCommand())
	if got := r.commands(); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", joined(got))
	}
}

// Connecting and disconnecting took seconds when every command was its own process run after the other.
func TestParallelAttachRunsEveryCommandAndStillRollsBackAFailedRoute(t *testing.T) {
	r := &recorder{fail: func(c []string) error {
		if slices.Contains(c, "prefix=128.0.0.0/1") && slices.Contains(c, "add") {
			return errors.New("netsh failed: access denied")
		}
		return nil
	}}
	n := New(Config{Run: r.run, AdapterExists: func(string) bool { return true }, Sleep: func(time.Duration) {}, Attempts: 1, Background: func(f func()) { f() }})

	if err := n.Attach(dnsPlan); err == nil {
		t.Fatal("a failed route must fail the attach")
	}
	ran := joined(r.commands())
	for _, c := range joined(addRouteCommands(dnsPlan)) {
		if !slices.Contains(ran, c) {
			t.Fatalf("every route was tried: missing %s", c)
		}
	}
	for _, c := range joined(deleteRouteCommands(dnsPlan)) {
		if !slices.Contains(ran, c) {
			t.Fatalf("the routes that went in were removed: missing %s", c)
		}
	}
}

func TestParallelAttachInstallsRoutesDnsAndTheBlockRule(t *testing.T) {
	r := &recorder{}
	n := New(Config{Run: r.run, AdapterExists: func(string) bool { return true }, Sleep: func(time.Duration) {}, Attempts: 1, Background: func(f func()) { f() }})
	if err := n.Attach(dnsPlan); err != nil {
		t.Fatal(err)
	}
	dns, _ := dnsCommand(dnsPlan)
	block, _ := multicastBlockCommand(dnsPlan)
	want := joined(append(addRouteCommands(dnsPlan), dns, block))
	got := joined(r.commands())
	slices.Sort(want)
	slices.Sort(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// Only the routes decide when the system's traffic is back on the real adapter; the firewall rule and the DNS
// cache are cleaned up behind the disconnect, not in front of it.
func TestDetachWaitsOnlyForTheRoutesAndLeavesTheRestToTheBackground(t *testing.T) {
	r := &recorder{}
	var background []func()
	n := serialNet(r, func(f func()) { background = append(background, f) })
	if err := n.Attach(dnsPlan); err != nil {
		t.Fatal(err)
	}
	background = nil
	r.reset()

	_ = n.Detach()
	if got := r.commands(); !reflect.DeepEqual(got, deleteRouteCommands(dnsPlan)) {
		t.Fatalf("only the routes are waited for: %v", joined(got))
	}
	for _, f := range background {
		f()
	}
	want := append(deleteRouteCommands(dnsPlan), multicastUnblockCommand(), dnsFlushCommand())
	if got := r.commands(); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", joined(got))
	}
}

func TestAttachDoesNotWaitForTheDnsAndTheBlockRule(t *testing.T) {
	r := &recorder{}
	var background []func()
	n := serialNet(r, func(f func()) { background = append(background, f) })

	if err := n.Attach(dnsPlan); err != nil {
		t.Fatal(err)
	}
	if got := r.commands(); !reflect.DeepEqual(got, addRouteCommands(dnsPlan)) {
		t.Fatalf("only the routes are waited for: %v", joined(got))
	}
	for _, f := range background {
		f()
	}
	if extra := len(r.commands()) - len(addRouteCommands(dnsPlan)); extra != 2 {
		t.Fatalf("the DNS and the block rule follow in the background, got %d", extra)
	}
}

// ---- stale adapters -------------------------------------------------------------------------------

func TestAnAdapterNamedLikeTheTunnelOrNumberedAfterItIsStale(t *testing.T) {
	for name, want := range map[string]bool{
		"skipi0": true, "skipi0 1": true, "skipi0 12": true,
		"Ethernet": false, "skipi01": false, "skipi0 x": false, "my skipi0": false, "Wi-Fi 2": false,
	} {
		if got := isStaleAdapter(name, "skipi0"); got != want {
			t.Errorf("%q: got %v want %v", name, got, want)
		}
	}
}

func TestWithNothingStaleTheRemovalIsNotStarted(t *testing.T) {
	removed := 0
	n := New(Config{
		ListAdapters:  func() ([]string, error) { return []string{"Ethernet", "Wi-Fi"}, nil },
		RemoveAdapter: func(string) error { removed++; return nil },
	})
	if err := n.RemoveStale("skipi0"); err != nil || removed != 0 {
		t.Fatalf("err=%v removed=%d", err, removed)
	}
}

func TestAStaleAdapterIsRemoved(t *testing.T) {
	var removed []string
	n := New(Config{
		ListAdapters:  func() ([]string, error) { return []string{"Ethernet", "skipi0 1"}, nil },
		RemoveAdapter: func(name string) error { removed = append(removed, name); return nil },
	})
	if err := n.RemoveStale("skipi0"); err != nil || !reflect.DeepEqual(removed, []string{"skipi0"}) {
		t.Fatalf("err=%v removed=%v", err, removed)
	}
}

func TestWhenTheListCannotBeReadTheRemovalRunsAnyway(t *testing.T) {
	removed := 0
	n := New(Config{
		ListAdapters:  func() ([]string, error) { return nil, errors.New("no list") },
		RemoveAdapter: func(string) error { removed++; return nil },
	})
	_ = n.RemoveStale("skipi0")
	if removed != 1 {
		t.Fatalf("removed = %d", removed)
	}
}

func TestPlanDecodesTheHostsDevicePlan(t *testing.T) {
	plan, err := ParsePlan(`{"name":"skipi0","mtu":1400,"addresses":["172.19.0.1/30"],"routes":["0.0.0.0/1"],"dns":["1.1.1.1"]}`)
	if err != nil || plan.Name != "skipi0" || !reflect.DeepEqual(plan.Routes, []string{"0.0.0.0/1"}) || !reflect.DeepEqual(plan.DNS, []string{"1.1.1.1"}) {
		t.Fatalf("%+v %v", plan, err)
	}
	if _, err := ParsePlan(`{"routes":["0.0.0.0/1"]}`); err == nil {
		t.Fatal("a plan needs the adapter name")
	}
}

func TestNativeRoutesStartNoProcessAndAreRemovedNatively(t *testing.T) {
	r := &recorder{}
	routes := &fakeRoutes{}
	n := nativeNet(r, routes)

	if err := n.Attach(ipv4Plan); err != nil {
		t.Fatal(err)
	}
	if want := []string{"skipi0 0.0.0.0/1", "skipi0 128.0.0.0/1"}; !reflect.DeepEqual(routes.added, want) {
		t.Fatalf("added %v", routes.added)
	}
	for _, c := range r.commands() {
		if c[0] == "netsh" {
			t.Fatalf("a native route must not start netsh: %v", c)
		}
	}

	_ = n.Detach()
	if want := []string{"skipi0 0.0.0.0/1", "skipi0 128.0.0.0/1"}; !reflect.DeepEqual(routes.deleted, want) {
		t.Fatalf("deleted %v", routes.deleted)
	}
}

// The native path is new; a route the system refuses natively is still installed the way it always was.
func TestAFailedNativeRouteFallsBackToNetsh(t *testing.T) {
	r := &recorder{}
	routes := &fakeRoutes{addErr: errors.New("ERROR_INVALID_PARAMETER")}
	n := nativeNet(r, routes)

	if err := n.Attach(ipv4Plan); err != nil {
		t.Fatalf("netsh must take over: %v", err)
	}
	var adds [][]string
	for _, c := range r.commands() {
		if c[0] == "netsh" && slices.Contains(c, "add") {
			adds = append(adds, c)
		}
	}
	if !reflect.DeepEqual(adds, addRouteCommands(ipv4Plan)) {
		t.Fatalf("got %v", adds)
	}
}
