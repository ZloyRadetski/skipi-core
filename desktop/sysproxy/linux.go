// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package sysproxy

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// The Linux backend drives GNOME (gsettings) and KDE (kwriteconfig) at once; whichever is installed
// is managed. The values go back even when the proxy was off: the exclusion list and the endpoints are
// the user's too and were overwritten while SKIPI owned the proxy.

const (
	gnomeSchema       = "org.gnome.system.proxy"
	gnomeDefaultHosts = "['localhost', '127.0.0.0/8', '::1']"
)

type linuxSnapshot struct {
	GnomeMode        string  `json:"gnomeMode"`
	GnomeHTTPHost    string  `json:"gnomeHttpHost"`
	GnomeHTTPPort    int     `json:"gnomeHttpPort"`
	GnomeHTTPEnabled bool    `json:"gnomeHttpEnabled"`
	GnomeHTTPSHost   string  `json:"gnomeHttpsHost"`
	GnomeHTTPSPort   int     `json:"gnomeHttpsPort"`
	GnomeSocksHost   string  `json:"gnomeSocksHost"`
	GnomeSocksPort   int     `json:"gnomeSocksPort"`
	GnomeIgnoreHosts string  `json:"gnomeIgnoreHosts"`
	KdeProxyType     *string `json:"kdeProxyType"`
	KdeHTTPProxy     *string `json:"kdeHttpProxy"`
	KdeHTTPSProxy    *string `json:"kdeHttpsProxy"`
	KdeSocksProxy    *string `json:"kdeSocksProxy"`
	KdeNoProxyFor    *string `json:"kdeNoProxyFor"`
}

type linuxBackend struct {
	run      Runner
	hasGnome bool
	kdeWrite string
	kdeRead  string
}

func newLinuxBackend(r Runner) *linuxBackend {
	b := &linuxBackend{run: r, hasGnome: r.Look("gsettings")}
	for _, name := range []string{"kwriteconfig6", "kwriteconfig5"} {
		if r.Look(name) {
			b.kdeWrite = name
			break
		}
	}
	for _, name := range []string{"kreadconfig6", "kreadconfig5"} {
		if r.Look(name) {
			b.kdeRead = name
			break
		}
	}
	return b
}

func (b *linuxBackend) Supported() bool { return b.hasGnome || b.kdeWrite != "" }

func (b *linuxBackend) Capture() (json.RawMessage, error) {
	s := linuxSnapshot{GnomeMode: "none", GnomeIgnoreHosts: gnomeDefaultHosts}
	if b.hasGnome {
		s.GnomeMode = orDefault(b.gsetting(gnomeSchema, "mode"), "none")
		s.GnomeHTTPHost = b.gsetting(gnomeSchema+".http", "host")
		s.GnomeHTTPPort, _ = strconv.Atoi(b.gsetting(gnomeSchema+".http", "port"))
		s.GnomeHTTPEnabled = b.gsetting(gnomeSchema+".http", "enabled") == "true"
		s.GnomeHTTPSHost = b.gsetting(gnomeSchema+".https", "host")
		s.GnomeHTTPSPort, _ = strconv.Atoi(b.gsetting(gnomeSchema+".https", "port"))
		s.GnomeSocksHost = b.gsetting(gnomeSchema+".socks", "host")
		s.GnomeSocksPort, _ = strconv.Atoi(b.gsetting(gnomeSchema+".socks", "port"))
		s.GnomeIgnoreHosts = orDefault(b.gsettingRaw("ignore-hosts"), gnomeDefaultHosts)
	}
	if b.kdeRead != "" {
		s.KdeProxyType = b.kdeValue("ProxyType")
		s.KdeHTTPProxy = b.kdeValue("httpProxy")
		s.KdeHTTPSProxy = b.kdeValue("httpsProxy")
		s.KdeSocksProxy = b.kdeValue("socksProxy")
		s.KdeNoProxyFor = b.kdeValue("NoProxyFor")
	}
	return json.Marshal(s)
}

func (b *linuxBackend) Apply(l Lease) error {
	var prev linuxSnapshot
	if err := json.Unmarshal(l.Snapshot, &prev); err != nil {
		return err
	}
	e := l.Endpoints
	if b.hasGnome {
		for _, w := range [][3]string{
			{gnomeSchema + ".http", "host", quote(e.Host)},
			{gnomeSchema + ".http", "port", strconv.Itoa(e.HTTPPort)},
			{gnomeSchema + ".http", "enabled", "true"},
			{gnomeSchema + ".https", "host", quote(e.Host)},
			{gnomeSchema + ".https", "port", strconv.Itoa(e.HTTPPort)},
			{gnomeSchema + ".socks", "host", quote(e.Host)},
			{gnomeSchema + ".socks", "port", strconv.Itoa(e.SocksPort)},
			{gnomeSchema, "ignore-hosts", mergeGsettingsIgnoreHosts(prev.GnomeIgnoreHosts)},
			{gnomeSchema, "mode", "manual"},
		} {
			if err := b.setGsetting(w[0], w[1], w[2]); err != nil {
				return err
			}
		}
	}
	if b.kdeWrite != "" {
		for _, w := range [][2]string{
			{"httpProxy", fmt.Sprintf("http://%s:%d", e.Host, e.HTTPPort)},
			{"httpsProxy", fmt.Sprintf("http://%s:%d", e.Host, e.HTTPPort)},
			{"socksProxy", fmt.Sprintf("socks5://%s:%d", e.Host, e.SocksPort)},
			{"NoProxyFor", mergeKdeNoProxyFor(deref(prev.KdeNoProxyFor))},
			{"ProxyType", "1"},
		} {
			if err := b.writeKde(w[0], w[1]); err != nil {
				return err
			}
		}
	}
	return nil
}

// Ownership: the desktop settings carry no mark, so a lease is trusted as it says itself.
func (b *linuxBackend) Ownership(l Lease) (Ownership, error) {
	if l.Phase == PhaseActive {
		return Active, nil
	}
	return Restorable, nil
}

func (b *linuxBackend) Restore(l Lease) error {
	var s linuxSnapshot
	if err := json.Unmarshal(l.Snapshot, &s); err != nil {
		return err
	}
	if b.hasGnome {
		for _, w := range [][3]string{
			{gnomeSchema + ".http", "host", quote(s.GnomeHTTPHost)},
			{gnomeSchema + ".http", "port", strconv.Itoa(s.GnomeHTTPPort)},
			{gnomeSchema + ".http", "enabled", strconv.FormatBool(s.GnomeHTTPEnabled)},
			{gnomeSchema + ".https", "host", quote(s.GnomeHTTPSHost)},
			{gnomeSchema + ".https", "port", strconv.Itoa(s.GnomeHTTPSPort)},
			{gnomeSchema + ".socks", "host", quote(s.GnomeSocksHost)},
			{gnomeSchema + ".socks", "port", strconv.Itoa(s.GnomeSocksPort)},
			{gnomeSchema, "ignore-hosts", s.GnomeIgnoreHosts},
			{gnomeSchema, "mode", orDefault(s.GnomeMode, "none")},
		} {
			if err := b.setGsetting(w[0], w[1], w[2]); err != nil {
				return err
			}
		}
	}
	if b.kdeWrite != "" {
		if err := b.writeKde("ProxyType", orDefault(deref(s.KdeProxyType), "0")); err != nil {
			return err
		}
		for _, w := range []struct {
			key   string
			value *string
		}{{"httpProxy", s.KdeHTTPProxy}, {"httpsProxy", s.KdeHTTPSProxy}, {"socksProxy", s.KdeSocksProxy}, {"NoProxyFor", s.KdeNoProxyFor}} {
			if w.value != nil {
				if err := b.writeKde(w.key, *w.value); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (b *linuxBackend) Discard(Lease) error { return nil }

// ForceClear is best effort: a desktop that refuses is not an error worth failing the button for.
func (b *linuxBackend) ForceClear() error {
	if b.hasGnome {
		_, _, _ = b.run.Run("gsettings", "set", gnomeSchema, "mode", "none")
	}
	if b.kdeWrite != "" {
		_, _, _ = b.run.Run(b.kdeWrite, "--file", "kioslaurc", "--group", "Proxy Settings", "--key", "ProxyType", "0")
	}
	return nil
}

func (b *linuxBackend) RepairStale() (bool, error) { return false, nil }

func (b *linuxBackend) gsettingRaw(key string) string {
	out, code, err := b.run.Run("gsettings", "get", gnomeSchema, key)
	if err != nil || code != 0 {
		return ""
	}
	return strings.TrimSpace(out)
}

func (b *linuxBackend) gsetting(schema, key string) string {
	out, code, err := b.run.Run("gsettings", "get", schema, key)
	if err != nil || code != 0 {
		return ""
	}
	value := strings.TrimSpace(out)
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
		value = value[1 : len(value)-1]
	}
	return value
}

func (b *linuxBackend) setGsetting(schema, key, value string) error {
	out, code, err := b.run.Run("gsettings", "set", schema, key, value)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("gsettings set %s %s %s failed: %s", schema, key, value, strings.TrimSpace(out))
	}
	return nil
}

func (b *linuxBackend) kdeValue(key string) *string {
	out, _, err := b.run.Run(b.kdeRead, "--file", "kioslaurc", "--group", "Proxy Settings", "--key", key)
	if err != nil {
		return nil
	}
	if v := strings.TrimSpace(out); v != "" {
		return &v
	}
	return nil
}

func (b *linuxBackend) writeKde(key, value string) error {
	out, code, err := b.run.Run(b.kdeWrite, "--file", "kioslaurc", "--group", "Proxy Settings", "--key", key, value)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%s failed to write %s: %s", b.kdeWrite, key, strings.TrimSpace(out))
	}
	return nil
}

func quote(s string) string { return "'" + s + "'" }

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var (
	gnomeRequiredHosts = []string{"localhost", "127.0.0.0/8", "::1"}
	kdeRequiredHosts   = []string{"localhost", "127.0.0.1", "::1"}
)

// mergeGsettingsIgnoreHosts is the user's GNOME exclusion list plus loopback, as a GVariant string
// array; nothing is listed twice.
func mergeGsettingsIgnoreHosts(existing string) string {
	text := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(existing), "@as"))
	text = strings.TrimSuffix(strings.TrimPrefix(text, "["), "]")
	var current []string
	for _, entry := range strings.Split(text, ",") {
		entry = strings.Trim(strings.TrimSpace(entry), `'"`)
		if entry != "" {
			current = append(current, entry)
		}
	}
	merged := distinctFold(append(current, gnomeRequiredHosts...))
	quoted := make([]string, len(merged))
	for i, entry := range merged {
		quoted[i] = quote(entry)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// mergeKdeNoProxyFor is the user's KDE exclusion list plus loopback, comma separated.
func mergeKdeNoProxyFor(existing string) string {
	var current []string
	for _, entry := range strings.Split(existing, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			current = append(current, entry)
		}
	}
	return strings.Join(distinctFold(append(current, kdeRequiredHosts...)), ",")
}
