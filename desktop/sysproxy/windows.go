// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package sysproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The Windows backend. It handles only the three WinINet registry values SKIPI changes; PAC/WPAD and
// WinHTTP are left alone. A marker under the SKIPI registry key says which lease owns the settings,
// so a stale lease never restores values the user or another client changed since.

const (
	windowsInternetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	windowsMarkerKey           = `Software\SKIPI\Desktop`
	windowsMarkerValue         = "SystemProxyLease"

	regString = "REG_SZ"
	regDword  = "REG_DWORD"
)

// RegValue is one registry value of the two kinds the proxy settings use.
type RegValue struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

// UnmarshalJSON also reads the type names the Kotlin host wrote ("String", "Dword").
func (v *RegValue) UnmarshalJSON(data []byte) error {
	var raw struct{ Type, Data string }
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	switch strings.ToLower(raw.Type) {
	case "string", "reg_sz":
		v.Type = regString
	case "dword", "reg_dword":
		v.Type = regDword
	default:
		return fmt.Errorf("unsupported registry value type %q", raw.Type)
	}
	v.Data = raw.Data
	return nil
}

func regDwordValue(n int) *RegValue     { return &RegValue{Type: regDword, Data: strconv.Itoa(n)} }
func regStringValue(s string) *RegValue { return &RegValue{Type: regString, Data: s} }

// Registry is the small surface of HKCU the backend needs; it cannot touch arbitrary keys.
type Registry interface {
	// Read returns nil, nil for a value that does not exist.
	Read(key, name string) (*RegValue, error)
	Write(key, name string, v RegValue) error
	// Delete is idempotent.
	Delete(key, name string) error
}

type windowsSnapshot struct {
	ProxyEnable   *RegValue `json:"proxyEnable"`
	ProxyServer   *RegValue `json:"proxyServer"`
	ProxyOverride *RegValue `json:"proxyOverride"`
	// AppliedOverride is the bypass list that was written; a lease of the old host carries it explicitly.
	AppliedOverride string `json:"appliedProxyOverride,omitempty"`
}

// applied is the bypass list the lease wrote, or the one it would write.
func (s windowsSnapshot) applied() string {
	if s.AppliedOverride != "" {
		return s.AppliedOverride
	}
	return appliedOverride(s.ProxyOverride)
}

type windowsBackend struct {
	reg      Registry
	refresh  func() error
	portOpen func(port int) bool
}

// newWindowsBackend builds the backend over a registry, the WinINet refresh and a probe that says
// whether anything accepts connections on a loopback port.
func newWindowsBackend(reg Registry, refresh func() error, portOpen func(int) bool) *windowsBackend {
	return &windowsBackend{reg: reg, refresh: refresh, portOpen: portOpen}
}

func (w *windowsBackend) Supported() bool { return true }

func proxyServerValue(e Endpoints) string {
	return fmt.Sprintf("http=%s:%d;https=%s:%d", e.Host, e.HTTPPort, e.Host, e.HTTPPort)
}

func (w *windowsBackend) read(name string) (*RegValue, error) {
	return w.reg.Read(windowsInternetSettingsKey, name)
}

func (w *windowsBackend) Capture() (json.RawMessage, error) {
	enable, err := w.read("ProxyEnable")
	if err != nil {
		return nil, err
	}
	server, err := w.read("ProxyServer")
	if err != nil {
		return nil, err
	}
	override, err := w.read("ProxyOverride")
	if err != nil {
		return nil, err
	}
	// A dead loopback proxy is what an earlier session of ours left behind, not the user's own
	// setting. Restoring it "enabled" would point every browser at a port nobody serves.
	if enable.isDword(1) && w.isDeadLoopbackProxy(server) {
		enable = regDwordValue(0)
	}
	return json.Marshal(windowsSnapshot{ProxyEnable: enable, ProxyServer: server, ProxyOverride: override})
}

func (w *windowsBackend) Apply(l Lease) error {
	var snap windowsSnapshot
	if err := json.Unmarshal(l.Snapshot, &snap); err != nil {
		return err
	}
	marker, err := w.reg.Read(windowsMarkerKey, windowsMarkerValue)
	if err != nil {
		return err
	}
	if marker != nil {
		return errors.New("another SKIPI system proxy lease marker is present; restart SKIPI or restore the proxy settings first")
	}
	steps := []struct {
		key, name string
		value     RegValue
	}{
		{windowsMarkerKey, windowsMarkerValue, *regStringValue(l.OwnerToken)},
		// The old proxy stays disabled until the complete endpoint is in place.
		{windowsInternetSettingsKey, "ProxyServer", *regStringValue(proxyServerValue(l.Endpoints))},
		{windowsInternetSettingsKey, "ProxyOverride", *regStringValue(snap.applied())},
		{windowsInternetSettingsKey, "ProxyEnable", *regDwordValue(1)},
	}
	for _, step := range steps {
		if err := w.reg.Write(step.key, step.name, step.value); err != nil {
			return err
		}
	}
	return w.refresh()
}

func (w *windowsBackend) Ownership(l Lease) (Ownership, error) {
	marker, err := w.reg.Read(windowsMarkerKey, windowsMarkerValue)
	if err != nil {
		return NotOwned, err
	}
	if marker == nil || marker.Type != regString || marker.Data != l.OwnerToken {
		return NotOwned, nil
	}
	var snap windowsSnapshot
	if err := json.Unmarshal(l.Snapshot, &snap); err != nil {
		return NotOwned, err
	}
	enable, err := w.read("ProxyEnable")
	if err != nil {
		return NotOwned, err
	}
	server, err := w.read("ProxyServer")
	if err != nil {
		return NotOwned, err
	}
	override, err := w.read("ProxyOverride")
	if err != nil {
		return NotOwned, err
	}
	applied := snap.applied()
	if enable.isDword(1) && server.matchesEndpoint(l.Endpoints) && override != nil && override.Type == regString && override.Data == applied {
		return Active, nil
	}
	// The marker is ours, but a change may have been interrupted: restoring is safe only if every value
	// is either the target or the captured original.
	known := enable.isEither(regDwordValue(1), snap.ProxyEnable) &&
		(server.matchesEndpoint(l.Endpoints) || server.isEither(regStringValue(proxyServerValue(l.Endpoints)), snap.ProxyServer)) &&
		override.isEither(regStringValue(applied), snap.ProxyOverride)
	if known {
		return Restorable, nil
	}
	return NotOwned, nil
}

// Restore writes the values back with ProxyEnable off first, so a transient state never sends traffic
// to the old endpoint. The marker stays until WinINet has acknowledged the refresh: a failed refresh
// is retryable.
func (w *windowsBackend) Restore(l Lease) error {
	marker, err := w.reg.Read(windowsMarkerKey, windowsMarkerValue)
	if err != nil {
		return err
	}
	if marker == nil || marker.Type != regString || marker.Data != l.OwnerToken {
		return errors.New("SKIPI no longer owns this Windows system proxy lease")
	}
	var snap windowsSnapshot
	if err := json.Unmarshal(l.Snapshot, &snap); err != nil {
		return err
	}
	if err := w.reg.Write(windowsInternetSettingsKey, "ProxyEnable", *regDwordValue(0)); err != nil {
		return err
	}
	for _, v := range []struct {
		name  string
		value *RegValue
	}{{"ProxyServer", snap.ProxyServer}, {"ProxyOverride", snap.ProxyOverride}, {"ProxyEnable", snap.ProxyEnable}} {
		if err := w.restoreValue(v.name, v.value); err != nil {
			return err
		}
	}
	if err := w.refresh(); err != nil {
		return err
	}
	return w.reg.Delete(windowsMarkerKey, windowsMarkerValue)
}

func (w *windowsBackend) restoreValue(name string, original *RegValue) error {
	if original == nil {
		return w.reg.Delete(windowsInternetSettingsKey, name)
	}
	return w.reg.Write(windowsInternetSettingsKey, name, *original)
}

// Discard removes only our marker; third-party settings stay.
func (w *windowsBackend) Discard(l Lease) error {
	marker, err := w.reg.Read(windowsMarkerKey, windowsMarkerValue)
	if err != nil {
		return err
	}
	if marker != nil && marker.Type == regString && marker.Data == l.OwnerToken {
		return w.reg.Delete(windowsMarkerKey, windowsMarkerValue)
	}
	return nil
}

// ForceClear runs every step whatever the others did and reports the first failure: the button used to
// say "done" while ProxyEnable stayed 1.
func (w *windowsBackend) ForceClear() error {
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	keep(w.reg.Write(windowsInternetSettingsKey, "ProxyEnable", *regDwordValue(0)))
	keep(w.refresh())
	keep(w.reg.Delete(windowsMarkerKey, windowsMarkerValue))
	return first
}

// RepairStale switches off an enabled proxy that points at a loopback port nobody serves: what a
// session that ended without handing the proxy back leaves. A live session's proxy (it has a marker),
// a proxy that answers and one that is not on loopback stay.
func (w *windowsBackend) RepairStale() (bool, error) {
	marker, err := w.reg.Read(windowsMarkerKey, windowsMarkerValue)
	if err != nil || marker != nil {
		return false, err
	}
	enable, err := w.read("ProxyEnable")
	if err != nil {
		return false, err
	}
	server, err := w.read("ProxyServer")
	if err != nil {
		return false, err
	}
	if !enable.isDword(1) || !w.isDeadLoopbackProxy(server) {
		return false, nil
	}
	if err := w.reg.Write(windowsInternetSettingsKey, "ProxyEnable", *regDwordValue(0)); err != nil {
		return false, err
	}
	return true, w.refresh()
}

var loopbackNames = map[string]bool{"127.0.0.1": true, "localhost": true, "[::1]": true}

func (w *windowsBackend) isDeadLoopbackProxy(server *RegValue) bool {
	endpoints, ok := server.proxyEndpoints()
	if !ok {
		return false
	}
	for _, e := range endpoints {
		if !loopbackNames[e.host] || w.portOpen(e.port) {
			return false
		}
	}
	return true
}

type hostPort struct {
	host string
	port int
}

// proxyEndpoints reads a ProxyServer value ("H:P", "http=H:P;https=H:P", "http://H:P").
func (v *RegValue) proxyEndpoints() ([]hostPort, bool) {
	if v == nil || v.Type != regString {
		return nil, false
	}
	text := strings.TrimSpace(v.Data)
	if text == "" {
		return nil, false
	}
	var out []hostPort
	for _, part := range strings.Split(text, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.Index(part, "="); i >= 0 {
			part = part[i+1:]
		}
		part = strings.TrimPrefix(strings.TrimPrefix(part, "http://"), "https://")
		part = strings.TrimRight(part, "/")
		i := strings.LastIndex(part, ":")
		if i <= 0 {
			return nil, false
		}
		port, err := strconv.Atoi(part[i+1:])
		if err != nil {
			return nil, false
		}
		out = append(out, hostPort{host: strings.ToLower(part[:i]), port: port})
	}
	return out, len(out) > 0
}

// matchesEndpoint reports whether the value points at the endpoint and nowhere else, however Windows
// wrote it: WinINet turns "http=H:P;https=H:P" into "H:P" when it refreshes.
func (v *RegValue) matchesEndpoint(e Endpoints) bool {
	endpoints, ok := v.proxyEndpoints()
	if !ok {
		return false
	}
	for _, hp := range endpoints {
		if hp.host != e.Host || hp.port != e.HTTPPort {
			return false
		}
	}
	return true
}

func (v *RegValue) isDword(want int) bool {
	if v == nil || v.Type != regDword {
		return false
	}
	n, ok := parseDword(v.Data)
	return ok && n == want
}

func (v *RegValue) isEither(expected, original *RegValue) bool {
	if v == nil {
		return original == nil && expected == nil
	}
	if expected != nil && *v == *expected || original != nil && *v == *original {
		return true
	}
	if v.Type == regDword {
		got, ok := parseDword(v.Data)
		for _, other := range []*RegValue{expected, original} {
			if other != nil && other.Type == regDword {
				if want, wok := parseDword(other.Data); ok && wok && got == want {
					return true
				}
			}
		}
	}
	return false
}

func parseDword(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ' '); i >= 0 {
		s = s[:i]
	}
	base := 10
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s, base = s[2:], 16
	}
	n, err := strconv.ParseInt(s, base, 64)
	if err != nil {
		return 0, false
	}
	return int(int32(n)), true
}

// appliedOverride is the user's bypass list plus loopback, nothing listed twice.
func appliedOverride(existing *RegValue) string {
	var current []string
	if existing != nil && existing.Type == regString {
		for _, entry := range strings.Split(existing.Data, ";") {
			if entry = strings.TrimSpace(entry); entry != "" {
				current = append(current, entry)
			}
		}
	}
	return strings.Join(distinctFold(append(current, "<local>", "localhost", "127.*", "[::1]")), ";")
}

func distinctFold(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range items {
		key := strings.ToLower(item)
		if !seen[key] {
			seen[key] = true
			out = append(out, item)
		}
	}
	return out
}
