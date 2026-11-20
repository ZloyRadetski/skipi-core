// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package winnet sets up the network around the Wintun adapter that hev creates on Windows: the routes
// that send the system's traffic into it, its DNS servers and interface metric, a firewall rule that keeps
// multicast out of it, and the removal of adapters an earlier session left behind.
//
// The sequencing and the rollback are plain Go over a few seams (the command runner and the adapter
// listing), so they are tested on every platform; only the defaults of those seams are Windows code.
package winnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

const routeMetric = 1

var adapterName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,14}$`)

// Plan is what the host describes: the adapter, the routes into it ("address/prefix") and the DNS servers.
type Plan struct {
	Name   string   `json:"name"`
	Routes []string `json:"routes"`
	DNS    []string `json:"dns"`
}

// ParsePlan reads the host's device plan (extra fields such as the MTU are ignored).
func ParsePlan(data string) (Plan, error) {
	var plan Plan
	if err := json.Unmarshal([]byte(data), &plan); err != nil {
		return Plan{}, fmt.Errorf("invalid TUN plan: %w", err)
	}
	if !adapterName.MatchString(plan.Name) {
		return Plan{}, errors.New("the TUN plan needs a plain adapter name")
	}
	return plan, nil
}

// Config holds the seams. Anything left nil takes the platform's default.
type Config struct {
	// Run runs one command to completion and fails on a non-zero exit.
	Run func(command []string) error
	// AdapterExists reports whether Windows knows an adapter with this name.
	AdapterExists func(name string) bool
	// ListAdapters returns the names of all adapters.
	ListAdapters func() ([]string, error)
	// RemoveAdapter removes the leftover Wintun adapters named like name.
	RemoveAdapter func(name string) error
	// AddRoute and DeleteRoute install an on-link route through the IP Helper API, without a process. They
	// are optional: without them, or when one fails, the route goes in through netsh as it always did.
	AddRoute    func(adapter string, prefix netip.Prefix) error
	DeleteRoute func(adapter string, prefix netip.Prefix) error
	// SetDNS gives the adapter its DNS servers and the lowest interface metric, and FlushDNS drops the resolver
	// cache; both through the system's API, without a process. Optional like the routes: without them, or when one
	// fails, the PowerShell script that did this before runs in the background.
	SetDNS   func(adapter string, servers []netip.Addr) error
	FlushDNS func() error

	Sleep    func(time.Duration)
	Attempts int           // polls for the adapter before giving up
	Poll     time.Duration // between polls
	// Serial runs the commands one after the other (tests); otherwise they run at once.
	Serial bool
	// Background runs what the connect or disconnect does not wait for; nil queues it behind earlier work.
	Background func(func())
}

// Net installs and removes the network setup of one tunnel session.
type Net struct {
	cfg Config

	mu         sync.Mutex
	attached   *Plan
	dnsApplied bool

	queueOnce sync.Once
	queue     chan func()
}

// New fills the seams that are nil.
func New(cfg Config) *Net {
	applyPlatformDefaults(&cfg)
	if cfg.Sleep == nil {
		cfg.Sleep = time.Sleep
	}
	if cfg.Attempts == 0 {
		cfg.Attempts = 400
	}
	if cfg.Poll == 0 {
		cfg.Poll = 10 * time.Millisecond
	}
	return &Net{cfg: cfg}
}

// Attach waits for the adapter and installs the routes, which is all that is waited for; the DNS servers and
// the firewall rule follow in the background, since neither decides whether the tunnel carries traffic (a
// discovery storm needs seconds to fill hev's sessions, and the first lookups of a second only go out of
// the old resolvers). A route that fails undoes the ones already in, so a half-routed tunnel never carries
// part of the traffic.
func (n *Net) Attach(plan Plan) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.awaitAdapter(plan.Name) {
		return fmt.Errorf("The TUN adapter %s did not appear", plan.Name)
	}
	dns, err := dnsCommand(plan)
	if err != nil {
		return err
	}
	block, err := multicastBlockCommand(plan)
	if err != nil {
		return err
	}
	servers := dnsServers(plan)
	n.dnsApplied = len(servers) > 0

	if failed := firstError(n.runAll(n.routeTasks(plan, true))); failed != nil {
		n.runAll(n.routeTasks(plan, false))
		_ = n.cfg.Run(multicastUnblockCommand())
		return failed
	}
	// The DNS servers decide where the first lookups go, so they are set before the connect returns; set natively
	// that is a call, not a process. Only when it fails does the old script follow in the background.
	if len(servers) > 0 && n.cfg.SetDNS != nil && n.cfg.SetDNS(plan.Name, servers) == nil {
		dns = nil
	}
	for _, command := range [][]string{dns, block} {
		if command != nil {
			command := command
			n.background(func() { _ = n.cfg.Run(command) })
		}
	}
	n.attached = &plan
	return nil
}

// Detach deletes the routes, the only thing the disconnect waits for: without them the adapter takes no
// traffic. A route that is already gone (the adapter was removed first) is not an error. The firewall rule
// and the DNS cache are cleaned up behind it.
func (n *Net) Detach() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	plan := n.attached
	if plan == nil {
		return nil
	}
	n.attached = nil
	n.runAll(n.routeTasks(*plan, false))
	flush := n.dnsApplied
	n.dnsApplied = false
	n.background(func() {
		_ = n.cfg.Run(multicastUnblockCommand())
		if flush && (n.cfg.FlushDNS == nil || n.cfg.FlushDNS() != nil) {
			_ = n.cfg.Run(dnsFlushCommand())
		}
	})
	return nil
}

// RemoveStale removes adapters an earlier session left behind: a hev process that is terminated cannot close
// its Wintun adapter, and Wintun then names the next one "skipi0 1". Removal is a PowerShell start and a
// pnputil call (most of a second), so a quick listing says first whether there is anything to remove. An
// unreadable listing runs the removal. It runs behind earlier background work and is waited for.
func (n *Net) RemoveStale(name string) error {
	if !adapterName.MatchString(name) {
		return errors.New("invalid adapter name")
	}
	done := make(chan error, 1)
	n.background(func() { done <- n.removeStale(name) })
	return <-done
}

// RemoveStaleLater is RemoveStale that nobody waits for: the disconnect does not need it.
func (n *Net) RemoveStaleLater(name string) {
	n.background(func() { _ = n.removeStale(name) })
}

func (n *Net) removeStale(name string) error {
	names, err := n.cfg.ListAdapters()
	if err == nil {
		stale := false
		for _, adapter := range names {
			if isStaleAdapter(adapter, name) {
				stale = true
				break
			}
		}
		if !stale {
			return nil
		}
	}
	return n.cfg.RemoveAdapter(name)
}

// isStaleAdapter: the tunnel's own name, or that name numbered by Wintun ("skipi0 1").
func isStaleAdapter(adapter, name string) bool {
	if adapter == name {
		return true
	}
	rest, ok := strings.CutPrefix(adapter, name+" ")
	if !ok || rest == "" {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (n *Net) background(task func()) {
	if n.cfg.Background != nil {
		n.cfg.Background(task)
		return
	}
	n.queueOnce.Do(func() {
		n.queue = make(chan func(), 64)
		go func() {
			for task := range n.queue {
				task()
			}
		}()
	})
	n.queue <- task
}

func (n *Net) awaitAdapter(name string) bool {
	for attempt := 0; attempt < n.cfg.Attempts; attempt++ {
		if n.cfg.AdapterExists(name) {
			return true
		}
		if attempt < n.cfg.Attempts-1 {
			n.cfg.Sleep(n.cfg.Poll)
		}
	}
	return false
}

// routeTasks is one task per route of the plan, adding them or deleting them. A task goes through the native
// call when there is one, and through netsh when there is none or the native call failed.
func (n *Net) routeTasks(plan Plan, add bool) []func() error {
	tasks := make([]func() error, 0, len(plan.Routes))
	for _, route := range plan.Routes {
		command := deleteRouteCommand(plan, route)
		native := n.cfg.DeleteRoute
		if add {
			command = addRouteCommand(plan, route)
			native = n.cfg.AddRoute
		}
		tasks = append(tasks, func() error {
			if native != nil {
				if prefix, err := netip.ParsePrefix(route); err == nil && native(plan.Name, prefix) == nil {
					return nil
				}
			}
			return n.cfg.Run(command)
		})
	}
	return tasks
}

// runAll runs the tasks, at once unless Serial, and returns each one's result in order.
func (n *Net) runAll(tasks []func() error) []error {
	results := make([]error, len(tasks))
	if n.cfg.Serial || len(tasks) < 2 {
		for i, task := range tasks {
			results[i] = task()
		}
		return results
	}
	var wg sync.WaitGroup
	for i, task := range tasks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = task()
		}()
	}
	wg.Wait()
	return results
}

func firstError(results []error) error {
	for _, err := range results {
		if err != nil {
			return err
		}
	}
	return nil
}

func routeFamily(prefix string) string {
	if strings.Contains(prefix, ":") {
		return "ipv6"
	}
	return "ipv4"
}

// addRouteCommands are the routes that send the system's traffic into the adapter, on link (it has no
// gateway) and only for this session: store=active keeps them out of the persistent route table.
func addRouteCommands(plan Plan) [][]string {
	commands := make([][]string, 0, len(plan.Routes))
	for _, prefix := range plan.Routes {
		commands = append(commands, addRouteCommand(plan, prefix))
	}
	return commands
}

func addRouteCommand(plan Plan, prefix string) []string {
	family := routeFamily(prefix)
	nextHop := "0.0.0.0"
	if family == "ipv6" {
		nextHop = "::"
	}
	return []string{
		"netsh", "interface", family, "add", "route",
		"prefix=" + prefix, "interface=" + plan.Name,
		"nexthop=" + nextHop, fmt.Sprintf("metric=%d", routeMetric), "store=active",
	}
}

func deleteRouteCommands(plan Plan) [][]string {
	commands := make([][]string, 0, len(plan.Routes))
	for _, prefix := range plan.Routes {
		commands = append(commands, deleteRouteCommand(plan, prefix))
	}
	return commands
}

func deleteRouteCommand(plan Plan, prefix string) []string {
	return []string{
		"netsh", "interface", routeFamily(prefix), "delete", "route",
		"prefix=" + prefix, "interface=" + plan.Name, "store=active",
	}
}

const multicastRuleName = "SKIPI TUN multicast block"

func powershell(script string) []string {
	return []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script}
}

// multicastBlockCommand blocks multicast and broadcast on this adapter only. Windows sends SSDP, LLMNR and
// mDNS discovery to every adapter, so a new tunnel adapter received about a thousand UDP flows within
// seconds; hev serves at most 1023 sessions at once and then fails every new socket, TCP included. The LAN
// keeps its discovery.
func multicastBlockCommand(plan Plan) ([]string, error) {
	if !adapterName.MatchString(plan.Name) {
		return nil, errors.New("invalid adapter name")
	}
	return powershell(fmt.Sprintf(
		"Remove-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue; "+
			"New-NetFirewallRule -DisplayName '%s' -Direction Outbound -Action Block "+
			"-InterfaceAlias '%s' -RemoteAddress 224.0.0.0/4,255.255.255.255,ff00::/8 | Out-Null",
		multicastRuleName, multicastRuleName, plan.Name)), nil
}

func multicastUnblockCommand() []string {
	return powershell(fmt.Sprintf("Remove-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue", multicastRuleName))
}

// dnsServers are the plan's DNS servers that are IP addresses; anything else is dropped.
func dnsServers(plan Plan) []netip.Addr {
	var servers []netip.Addr
	for _, server := range plan.DNS {
		if addr, err := netip.ParseAddr(strings.TrimSpace(server)); err == nil {
			servers = append(servers, addr)
		}
	}
	return servers
}

// dnsCommand gives the adapter the plan's DNS servers and the lowest interface metric. Windows keeps the DNS
// servers of the physical adapter and its DNS client sends a query out of the adapter that owns the server,
// so a tunnel adapter without DNS never resolves through the tunnel. Nil when the plan has no DNS: the system
// keeps its own resolvers. Only IP addresses are accepted into the script.
func dnsCommand(plan Plan) ([]string, error) {
	if !adapterName.MatchString(plan.Name) {
		return nil, errors.New("invalid adapter name")
	}
	var servers []string
	for _, addr := range dnsServers(plan) {
		servers = append(servers, "'"+addr.String()+"'")
	}
	if len(servers) == 0 {
		return nil, nil
	}
	return powershell(fmt.Sprintf(
		"$ErrorActionPreference = 'Stop'; "+
			"Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses (%s); "+
			"Set-NetIPInterface -InterfaceAlias '%s' -InterfaceMetric %d -ErrorAction SilentlyContinue; "+
			"Clear-DnsClientCache",
		plan.Name, strings.Join(servers, ","), plan.Name, routeMetric)), nil
}

// dnsFlushCommand drops the answers cached while the tunnel resolved, so the system's own resolvers are asked again.
func dnsFlushCommand() []string { return powershell("Clear-DnsClientCache") }
