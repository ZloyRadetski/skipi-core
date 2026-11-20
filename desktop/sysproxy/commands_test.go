// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package sysproxy

import (
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ---- Linux -----------------------------------------------------------------------------------

// fakeLinux models gsettings and the KDE config tools as key/value stores.
type fakeLinux struct {
	have    map[string]bool   // executables on PATH
	gsets   map[string]string // "schema key" -> text as gsettings prints it
	kde     map[string]string
	failSet bool
}

func newFakeLinux() *fakeLinux {
	return &fakeLinux{
		have: map[string]bool{"gsettings": true, "kwriteconfig6": true, "kreadconfig6": true},
		gsets: map[string]string{
			"org.gnome.system.proxy mode":         "'none'",
			"org.gnome.system.proxy.http host":    "''",
			"org.gnome.system.proxy.http port":    "0",
			"org.gnome.system.proxy.http enabled": "false",
			"org.gnome.system.proxy.https host":   "''",
			"org.gnome.system.proxy.https port":   "0",
			"org.gnome.system.proxy.socks host":   "''",
			"org.gnome.system.proxy.socks port":   "0",
			"org.gnome.system.proxy ignore-hosts": "['localhost', '127.0.0.0/8', '::1', '*.corp']",
		},
		kde: map[string]string{"ProxyType": "0", "NoProxyFor": "intranet"},
	}
}

func (f *fakeLinux) Look(name string) bool { return f.have[name] }

func (f *fakeLinux) Run(name string, args ...string) (string, int, error) {
	switch name {
	case "gsettings":
		if args[0] == "get" {
			v, ok := f.gsets[args[1]+" "+args[2]]
			if !ok {
				return "No such key", 1, nil
			}
			return v + "\n", 0, nil
		}
		if f.failSet {
			return "denied", 1, nil
		}
		value := args[3]
		if args[2] == "mode" && !strings.HasPrefix(value, "'") {
			value = "'" + value + "'" // gsettings prints an enum quoted, whichever way it was set
		}
		f.gsets[args[1]+" "+args[2]] = value
		return "", 0, nil
	case "kreadconfig6":
		return f.kde[args[len(args)-1]] + "\n", 0, nil
	case "kwriteconfig6":
		f.kde[args[len(args)-2]] = args[len(args)-1]
		return "", 0, nil
	}
	return "", 127, fmt.Errorf("unexpected command %s", name)
}

func newLinuxRig(t *testing.T) (*Manager, *fakeLinux) {
	t.Helper()
	f := newFakeLinux()
	return NewManager(newLinuxBackend(f), filepath.Join(t.TempDir(), "lease.json")), f
}

func TestLinuxAcquireSetsGnomeAndKdeAndReleaseRestoresTheExactValues(t *testing.T) {
	m, f := newLinuxRig(t)
	before := map[string]string{}
	for k, v := range f.gsets {
		before[k] = v
	}

	res, err := m.Acquire(testEndpoints)
	mustAction(t, res, err, ActionAcquired)
	if f.gsets["org.gnome.system.proxy mode"] != "'manual'" ||
		f.gsets["org.gnome.system.proxy.http host"] != "'127.0.0.1'" ||
		f.gsets["org.gnome.system.proxy.http port"] != "10809" ||
		f.gsets["org.gnome.system.proxy.socks port"] != "10808" {
		t.Fatalf("GNOME not pointed at the proxy: %v", f.gsets)
	}
	if f.kde["ProxyType"] != "1" || f.kde["httpProxy"] != "http://127.0.0.1:10809" || f.kde["socksProxy"] != "socks5://127.0.0.1:10808" {
		t.Fatalf("KDE not pointed at the proxy: %v", f.kde)
	}
	// The user's own exclusions stay while the proxy is on, loopback is always there.
	hosts := f.gsets["org.gnome.system.proxy ignore-hosts"]
	if !strings.Contains(hosts, "'*.corp'") || strings.Count(hosts, "'localhost'") != 1 {
		t.Fatalf("ignore-hosts = %s", hosts)
	}
	if f.kde["NoProxyFor"] != "intranet,localhost,127.0.0.1,::1" {
		t.Fatalf("NoProxyFor = %s", f.kde["NoProxyFor"])
	}

	res, err = m.Release()
	mustAction(t, res, err, ActionReleased)
	if !reflect.DeepEqual(f.gsets, before) {
		t.Fatalf("GNOME values must come back exactly:\n got %v\nwant %v", f.gsets, before)
	}
	if f.kde["ProxyType"] != "0" || f.kde["NoProxyFor"] != "intranet" {
		t.Fatalf("KDE values must come back: %v", f.kde)
	}
}

func TestLinuxRestoresAProxyTheUserAlreadyHad(t *testing.T) {
	m, f := newLinuxRig(t)
	f.gsets["org.gnome.system.proxy mode"] = "'manual'"
	f.gsets["org.gnome.system.proxy.http host"] = "'proxy.corp'"
	f.gsets["org.gnome.system.proxy.http port"] = "3128"
	f.gsets["org.gnome.system.proxy.http enabled"] = "true"

	if _, err := m.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Release(); err != nil {
		t.Fatal(err)
	}
	if f.gsets["org.gnome.system.proxy.http host"] != "'proxy.corp'" || f.gsets["org.gnome.system.proxy.http port"] != "3128" ||
		f.gsets["org.gnome.system.proxy mode"] != "'manual'" {
		t.Fatalf("the user's proxy must come back: %v", f.gsets)
	}
}

func TestLinuxManagesOnlyWhatIsInstalled(t *testing.T) {
	f := newFakeLinux()
	f.have = map[string]bool{"gsettings": true} // no KDE tools
	m := NewManager(newLinuxBackend(f), filepath.Join(t.TempDir(), "lease.json"))
	if _, err := m.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	if f.kde["ProxyType"] != "0" {
		t.Fatal("KDE must stay untouched without its tools")
	}
	if !m.Supported() {
		t.Fatal("GNOME alone is enough")
	}
	f.have = map[string]bool{}
	if newLinuxBackend(f).Supported() {
		t.Fatal("no desktop tools, no system proxy")
	}
}

func TestLinuxAFailedGsettingsWriteRollsBack(t *testing.T) {
	m, f := newLinuxRig(t)
	f.failSet = true
	if _, err := m.Acquire(testEndpoints); err == nil || !strings.Contains(err.Error(), "gsettings") {
		t.Fatalf("got %v", err)
	}
}

func TestLinuxForceClearSwitchesBothDesktopsOff(t *testing.T) {
	m, f := newLinuxRig(t)
	if _, err := m.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	if err := m.ForceClear(); err != nil {
		t.Fatal(err)
	}
	if f.gsets["org.gnome.system.proxy mode"] != "'none'" || f.kde["ProxyType"] != "0" {
		t.Fatalf("gnome=%s kde=%s", f.gsets["org.gnome.system.proxy mode"], f.kde["ProxyType"])
	}
}

func TestMergedExclusionListsKeepTheUsersEntriesAndAddLoopbackOnce(t *testing.T) {
	if got := mergeGsettingsIgnoreHosts("@as ['a.corp', 'LOCALHOST']"); got != "['a.corp', 'LOCALHOST', '127.0.0.0/8', '::1']" {
		t.Fatalf("got %s", got)
	}
	if got := mergeKdeNoProxyFor(""); got != "localhost,127.0.0.1,::1" {
		t.Fatalf("got %s", got)
	}
}

// ---- macOS -----------------------------------------------------------------------------------

type macSettings struct {
	web, secureWeb, socks MacProxyState
	bypass                []string
}

// fakeMac models networksetup for a set of services.
type fakeMac struct {
	order    []string
	disabled map[string]bool
	services map[string]*macSettings
	unread   map[string]bool // services whose settings cannot be read
	ran      []string
}

func newFakeMac() *fakeMac {
	return &fakeMac{
		order:    []string{"Wi-Fi", "Ethernet", "Old VPN"},
		disabled: map[string]bool{"Old VPN": true},
		services: map[string]*macSettings{
			"Wi-Fi":    {web: MacProxyState{false, "", 0}, secureWeb: MacProxyState{false, "", 0}, socks: MacProxyState{true, "10.0.0.1", 1080}, bypass: []string{"*.local"}},
			"Ethernet": {web: MacProxyState{true, "proxy.corp", 3128}, secureWeb: MacProxyState{true, "proxy.corp", 3128}, socks: MacProxyState{false, "", 0}},
			"Old VPN":  {},
		},
		unread: map[string]bool{},
	}
}

func (f *fakeMac) Look(name string) bool { return name == "networksetup" }

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func (f *fakeMac) Run(name string, args ...string) (string, int, error) {
	f.ran = append(f.ran, strings.Join(args, " "))
	cmd := args[0]
	if cmd == "-listallnetworkservices" {
		out := "An asterisk (*) denotes that a network service is disabled.\n"
		for _, s := range f.order {
			if f.disabled[s] {
				out += "*"
			}
			out += s + "\n"
		}
		return out, 0, nil
	}
	service := args[1]
	st, ok := f.services[service]
	if !ok || f.unread[service] {
		return "service unreadable", 1, nil
	}
	report := func(p MacProxyState) string {
		return fmt.Sprintf("Enabled: %s\nServer: %s\nPort: %d\nAuthenticated Proxy Enabled: 0\n", yesNo(p.Enabled), p.Host, p.Port)
	}
	kind := func() *MacProxyState {
		switch {
		case strings.Contains(cmd, "securewebproxy"):
			return &st.secureWeb
		case strings.Contains(cmd, "webproxy"):
			return &st.web
		case strings.Contains(cmd, "socksfirewallproxy"):
			return &st.socks
		}
		return nil
	}
	switch {
	case cmd == "-getwebproxy":
		return report(st.web), 0, nil
	case cmd == "-getsecurewebproxy":
		return report(st.secureWeb), 0, nil
	case cmd == "-getsocksfirewallproxy":
		return report(st.socks), 0, nil
	case cmd == "-getproxybypassdomains":
		if len(st.bypass) == 0 {
			return "There aren't any bypass domains set on " + service + ".\n", 0, nil
		}
		return strings.Join(st.bypass, "\n") + "\n", 0, nil
	case cmd == "-setproxybypassdomains":
		if args[2] == "Empty" {
			st.bypass = nil
		} else {
			st.bypass = append([]string(nil), args[2:]...)
		}
		return "", 0, nil
	case strings.HasSuffix(cmd, "proxystate"):
		kind().Enabled = args[2] == "on"
		return "", 0, nil
	case strings.HasPrefix(cmd, "-set") && strings.HasSuffix(cmd, "proxy"):
		p := kind()
		p.Host = args[2]
		p.Port, _ = strconv.Atoi(args[3])
		p.Enabled = true // networksetup enables a proxy it was given
		return "", 0, nil
	}
	return "unknown", 1, nil
}

func (f *fakeMac) snapshot() map[string]macSettings {
	out := map[string]macSettings{}
	for k, v := range f.services {
		c := *v
		c.bypass = append([]string(nil), v.bypass...)
		out[k] = c
	}
	return out
}

func newMacRig(t *testing.T) (*Manager, *fakeMac) {
	t.Helper()
	f := newFakeMac()
	return NewManager(newMacBackend(f), filepath.Join(t.TempDir(), "lease.json")), f
}

func TestMacAcquireSwitchesOnEveryEnabledServiceAndSkipsDisabledOnes(t *testing.T) {
	m, f := newMacRig(t)

	res, err := m.Acquire(testEndpoints)
	mustAction(t, res, err, ActionAcquired)
	for _, name := range []string{"Wi-Fi", "Ethernet"} {
		s := f.services[name]
		if s.web != (MacProxyState{true, "127.0.0.1", 10809}) || s.secureWeb != (MacProxyState{true, "127.0.0.1", 10809}) ||
			s.socks != (MacProxyState{true, "127.0.0.1", 10808}) {
			t.Fatalf("%s: %+v", name, s)
		}
	}
	if !reflect.DeepEqual(f.services["Wi-Fi"].bypass, []string{"*.local", "localhost", "127.0.0.1", "::1"}) {
		t.Fatalf("the bypass list keeps the user's entries and adds loopback: %v", f.services["Wi-Fi"].bypass)
	}
	if f.services["Old VPN"].web.Enabled {
		t.Fatal("a disabled service is left alone")
	}
}

func TestMacReleaseRestoresEachServicesOwnSettingsExactly(t *testing.T) {
	m, f := newMacRig(t)
	before := f.snapshot()

	if _, err := m.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	res, err := m.Release()
	mustAction(t, res, err, ActionReleased)
	if got := f.snapshot(); !reflect.DeepEqual(got, before) {
		t.Fatalf("settings must come back exactly:\n got %+v\nwant %+v", got, before)
	}
}

func TestMacAServiceThatCannotBeReadDoesNotStopTheOthers(t *testing.T) {
	m, f := newMacRig(t)
	f.unread["Ethernet"] = true

	if _, err := m.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	if !f.services["Wi-Fi"].web.Enabled || f.services["Ethernet"].web.Host != "proxy.corp" {
		t.Fatalf("only the readable service changes: %+v %+v", f.services["Wi-Fi"].web, f.services["Ethernet"].web)
	}
}

func TestMacAServiceThatVanishedMeanwhileDoesNotFailTheRestore(t *testing.T) {
	m, f := newMacRig(t)
	if _, err := m.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	f.order = []string{"Wi-Fi"}
	delete(f.services, "Ethernet")

	if _, err := m.Release(); err != nil {
		t.Fatalf("a vanished service must not fail the restore: %v", err)
	}
}

func TestMacForceClearSwitchesTheProxiesOffAndDropsTheLease(t *testing.T) {
	m, f := newMacRig(t)
	if _, err := m.Acquire(testEndpoints); err != nil {
		t.Fatal(err)
	}
	if err := m.ForceClear(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Wi-Fi", "Ethernet"} {
		s := f.services[name]
		if s.web.Enabled || s.secureWeb.Enabled || s.socks.Enabled {
			t.Fatalf("%s still has a proxy on: %+v", name, s)
		}
	}
	res, err := m.Recover()
	mustAction(t, res, err, ActionNothingToRelease)
}

func TestMacSupportedOnlyWhenNetworksetupAnswers(t *testing.T) {
	_, f := newMacRig(t)
	if !newMacBackend(f).Supported() {
		t.Fatal("networksetup answers")
	}
	f.order = nil
	// An empty list still answers; a missing tool does not.
	if !newMacBackend(f).Supported() {
		t.Fatal("an empty service list is still supported")
	}
	if newMacBackend(missingTools{}).Supported() {
		t.Fatal("without networksetup there is no system proxy")
	}
}

type missingTools struct{}

func (missingTools) Look(string) bool { return false }
func (missingTools) Run(string, ...string) (string, int, error) {
	return "", 127, fmt.Errorf("not found")
}

func TestMacParsers(t *testing.T) {
	services := parseMacNetworkServices("An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Old\n\n")
	want := []macService{{"Wi-Fi", true}, {"Old", false}}
	if !reflect.DeepEqual(services, want) {
		t.Fatalf("got %+v", services)
	}
	if st, ok := parseMacProxyState("Enabled: Yes\nServer: h\nPort: 8\n"); !ok || st != (MacProxyState{true, "h", 8}) {
		t.Fatalf("got %+v %v", st, ok)
	}
	if _, ok := parseMacProxyState("garbage"); ok {
		t.Fatal("garbage is not a proxy report")
	}
	if got := parseMacBypassDomains("There aren't any bypass domains set on Wi-Fi.\n"); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	if got := mergeMacBypassDomains([]string{"A", "localhost"}); !sort.StringsAreSorted([]string{}) || !reflect.DeepEqual(got, []string{"A", "localhost", "127.0.0.1", "::1"}) {
		t.Fatalf("got %v", got)
	}
}
