// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package sysproxy

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// The macOS backend goes through networksetup: every enabled network service gets the web, secure web
// and SOCKS proxy, and the settings each service had are written back on release.

const networksetup = "networksetup"

// MacProxyState is one proxy kind (web, secure web or SOCKS) of one network service.
type MacProxyState struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
}

type macServiceSnapshot struct {
	Service   string        `json:"service"`
	Web       MacProxyState `json:"web"`
	SecureWeb MacProxyState `json:"secureWeb"`
	Socks     MacProxyState `json:"socks"`
	Bypass    []string      `json:"bypass"`
}

type macService struct {
	name    string
	enabled bool
}

type macBackend struct{ run Runner }

func newMacBackend(r Runner) *macBackend { return &macBackend{run: r} }

func (b *macBackend) Supported() bool {
	if !b.run.Look(networksetup) {
		return false
	}
	_, code, err := b.run.Run(networksetup, "-listallnetworkservices")
	return err == nil && code == 0
}

func (b *macBackend) Capture() (json.RawMessage, error) {
	services, err := b.listServices()
	if err != nil {
		return nil, err
	}
	snapshots := []macServiceSnapshot{}
	for _, s := range services {
		if !s.enabled {
			continue
		}
		// A service whose settings cannot be read (a VPN pseudo-service, one that just vanished) is left out.
		if snap, err := b.readService(s.name); err == nil {
			snapshots = append(snapshots, snap)
		}
	}
	return json.Marshal(snapshots)
}

func (b *macBackend) readService(name string) (macServiceSnapshot, error) {
	snap := macServiceSnapshot{Service: name}
	var err error
	if snap.Web, err = b.readProxy("-getwebproxy", name); err != nil {
		return snap, err
	}
	if snap.SecureWeb, err = b.readProxy("-getsecurewebproxy", name); err != nil {
		return snap, err
	}
	if snap.Socks, err = b.readProxy("-getsocksfirewallproxy", name); err != nil {
		return snap, err
	}
	out, err := b.must("-getproxybypassdomains", name)
	if err != nil {
		return snap, err
	}
	snap.Bypass = parseMacBypassDomains(out)
	return snap, nil
}

func (b *macBackend) Apply(l Lease) error {
	var snaps []macServiceSnapshot
	if err := json.Unmarshal(l.Snapshot, &snaps); err != nil {
		return err
	}
	e := l.Endpoints
	for _, s := range snaps {
		if _, err := b.must("-setwebproxy", s.Service, e.Host, strconv.Itoa(e.HTTPPort)); err != nil {
			return err
		}
		if _, err := b.must("-setsecurewebproxy", s.Service, e.Host, strconv.Itoa(e.HTTPPort)); err != nil {
			return err
		}
		if _, err := b.must("-setsocksfirewallproxy", s.Service, e.Host, strconv.Itoa(e.SocksPort)); err != nil {
			return err
		}
		if err := b.setBypass(s.Service, mergeMacBypassDomains(s.Bypass)); err != nil {
			return err
		}
	}
	return nil
}

// Ownership: macOS keeps no mark, so a lease is trusted as it says itself.
func (b *macBackend) Ownership(l Lease) (Ownership, error) {
	if l.Phase == PhaseActive {
		return Active, nil
	}
	return Restorable, nil
}

func (b *macBackend) Restore(l Lease) error {
	var snaps []macServiceSnapshot
	if err := json.Unmarshal(l.Snapshot, &snaps); err != nil {
		return err
	}
	services, err := b.listServices()
	if err != nil {
		return err
	}
	present := map[string]bool{}
	for _, s := range services {
		present[s.name] = true
	}
	for _, s := range snaps {
		if !present[s.Service] {
			continue // the service vanished meanwhile
		}
		// The endpoint goes back even when the proxy was off: host and port are the user's too.
		for _, k := range []struct {
			kind  string
			state MacProxyState
		}{{"web", s.Web}, {"secureweb", s.SecureWeb}, {"socksfirewall", s.Socks}} {
			if _, err := b.must("-set"+k.kind+"proxy", s.Service, k.state.Host, strconv.Itoa(k.state.Port)); err != nil {
				return err
			}
			on := "off"
			if k.state.Enabled {
				on = "on"
			}
			if _, err := b.must("-set"+k.kind+"proxystate", s.Service, on); err != nil {
				return err
			}
		}
		if err := b.setBypass(s.Service, s.Bypass); err != nil {
			return err
		}
	}
	return nil
}

func (b *macBackend) Discard(Lease) error { return nil }

func (b *macBackend) ForceClear() error {
	services, _ := b.listServices()
	for _, s := range services {
		if !s.enabled {
			continue
		}
		for _, cmd := range []string{"-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate"} {
			_, _, _ = b.run.Run(networksetup, cmd, s.name, "off")
		}
	}
	return nil
}

func (b *macBackend) RepairStale() (bool, error) { return false, nil }

func (b *macBackend) listServices() ([]macService, error) {
	out, err := b.must("-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	return parseMacNetworkServices(out), nil
}

func (b *macBackend) readProxy(command, service string) (MacProxyState, error) {
	out, err := b.must(command, service)
	if err != nil {
		return MacProxyState{}, err
	}
	state, ok := parseMacProxyState(out)
	if !ok {
		return MacProxyState{}, fmt.Errorf("unreadable proxy report for %s", service)
	}
	return state, nil
}

func (b *macBackend) setBypass(service string, domains []string) error {
	if len(domains) == 0 {
		domains = []string{"Empty"}
	}
	_, err := b.must(append([]string{"-setproxybypassdomains", service}, domains...)...)
	return err
}

// must runs networksetup and fails on a non-zero exit.
func (b *macBackend) must(args ...string) (string, error) {
	out, code, err := b.run.Run(networksetup, args...)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("networksetup %s failed: %s", strings.Join(args[:min(len(args), 2)], " "), strings.TrimSpace(out))
	}
	return out, nil
}

func parseMacNetworkServices(output string) []macService {
	var services []macService
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, " \t\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "An asterisk (*)") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			services = append(services, macService{name: strings.TrimPrefix(line, "*")})
		} else {
			services = append(services, macService{name: line, enabled: true})
		}
	}
	return services
}

func parseMacProxyState(output string) (MacProxyState, bool) {
	fields := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if key, value, ok := strings.Cut(line, ":"); ok {
			if key = strings.TrimSpace(key); key != "" {
				fields[key] = strings.TrimSpace(value)
			}
		}
	}
	enabled, ok := fields["Enabled"]
	if !ok {
		return MacProxyState{}, false
	}
	port, err := strconv.Atoi(fields["Port"])
	if err != nil {
		return MacProxyState{}, false
	}
	return MacProxyState{Enabled: strings.EqualFold(enabled, "Yes"), Host: fields["Server"], Port: port}, true
}

func parseMacBypassDomains(output string) []string {
	var domains []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "There aren't any bypass domains") {
			continue
		}
		domains = append(domains, line)
	}
	return domains
}

// mergeMacBypassDomains is the user's own bypass list plus loopback; nothing is listed twice.
func mergeMacBypassDomains(existing []string) []string {
	return distinctFold(append(append([]string{}, existing...), "localhost", "127.0.0.1", "::1"))
}
