// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hevtun

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// Ported from desktopApp DesktopMacTunTest.kt (the supervisor, the launch command and the
// launch-failure text).

const testHev = "/Applications/SKIPI.app/Contents/Resources/hev/hev-socks5-tunnel"

func testSpec(mut func(*MacTunSupervisorSpec)) MacTunSupervisorSpec {
	s := MacTunSupervisorSpec{
		InterfaceName: "utun9",
		MTU:           1400,
		IPv4Address:   "172.19.0.1",
		Routes:        []string{"0.0.0.0/1", "128.0.0.0/1"},
		HevExecutable: testHev,
		HevConfig:     "/Users/test/SKIPI/run/tun-hev.yaml",
		StopFile:      "/Users/test/SKIPI/run/tun-stop",
		ReadyFile:     "/Users/test/SKIPI/run/tun-ready",
		ErrorFile:     "/Users/test/SKIPI/run/tun-error",
		AppPid:        4242,
		UserUid:       501,
	}
	if mut != nil {
		mut(&s)
	}
	return s
}

func mustScript(t *testing.T, mut func(*MacTunSupervisorSpec)) string {
	t.Helper()
	s, err := MacTunSupervisorScript(testSpec(mut))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func wantIn(t *testing.T, text, sub string) {
	t.Helper()
	if !strings.Contains(text, sub) {
		t.Fatalf("missing %q in:\n%s", sub, text)
	}
}

func TestScriptStartsHevWaitsForInterfaceAndInstallsEveryRoute(t *testing.T) {
	s := mustScript(t, nil)
	wantIn(t, s, "'"+testHev+"' '/Users/test/SKIPI/run/tun-hev.yaml'")
	wantIn(t, s, `ifconfig "$IFACE"`)
	wantIn(t, s, `ifconfig "$IFACE" inet '172.19.0.1' '172.19.0.1' mtu 1400 up`)
	wantIn(t, s, `route -n add -net '0.0.0.0/1' -interface "$IFACE"`)
	wantIn(t, s, `route -n add -net '128.0.0.0/1' -interface "$IFACE"`)
}

func TestIPv6RoutesUseTheInet6Family(t *testing.T) {
	s := mustScript(t, func(sp *MacTunSupervisorSpec) { sp.Routes = []string{"0.0.0.0/1", "::/1", "8000::/1"} })
	wantIn(t, s, `route -n add -inet6 -net '::/1' -interface "$IFACE"`)
	wantIn(t, s, `route -n add -inet6 -net '8000::/1' -interface "$IFACE"`)
	wantIn(t, s, `route -n add -net '0.0.0.0/1' -interface`)
}

func TestEveryAddedRouteIsDeletedOnCleanup(t *testing.T) {
	s := mustScript(t, func(sp *MacTunSupervisorSpec) { sp.Routes = []string{"0.0.0.0/1", "::/1"} })
	_, after, _ := strings.Cut(s, "cleanup()")
	cleanup, _, _ := strings.Cut(after, "\n}")
	wantIn(t, cleanup, `route -n delete -net '0.0.0.0/1' -interface "$IFACE"`)
	wantIn(t, cleanup, `route -n delete -inet6 -net '::/1' -interface "$IFACE"`)
	wantIn(t, cleanup, `kill "$HEV_PID"`)
	wantIn(t, cleanup, `rm -f "$READY"`)
}

func TestSessionEndsWhenCoreAsksHevDiesOrCoreIsGone(t *testing.T) {
	s := mustScript(t, nil)
	wantIn(t, s, "APP_PID=4242")
	wantIn(t, s, `kill -0 "$APP_PID"`)
	wantIn(t, s, `kill -0 "$HEV_PID"`)
	wantIn(t, s, `[ ! -e "$STOP" ]`)
	wantIn(t, s, "trap ")
}

func TestMarkersAreHandedBackToTheUser(t *testing.T) {
	s := mustScript(t, nil)
	wantIn(t, s, `chown 501 "$READY"`)
	wantIn(t, s, `chown 501 "$ERR"`)
}

func TestSupervisorMakesHevExecutableBeforeStartingIt(t *testing.T) {
	s := mustScript(t, nil)
	hev := "'" + testHev + "'"
	repair := strings.Index(s, "[ -x "+hev+" ] || chmod 755 "+hev)
	start := strings.Index(s, hev+" '/Users/test/SKIPI/run/tun-hev.yaml'")
	if repair < 0 {
		t.Fatal("no repair of the executable bit:\n" + s)
	}
	if start <= repair {
		t.Fatal("the repair must come before hev is started")
	}
	if !strings.Contains(s[repair:start], "|| fail") {
		t.Fatal("a failed repair is reported, not ignored")
	}
}

func TestSupervisorRaisesDescriptorLimitBeforeStartingHev(t *testing.T) {
	s := mustScript(t, nil)
	hev := "'" + testHev + "'"
	raise := strings.Index(s, "ulimit -n 10240")
	start := strings.Index(s, hev+" '/Users/test/SKIPI/run/tun-hev.yaml'")
	if raise < 0 {
		t.Fatal("no ulimit raise:\n" + s)
	}
	if start <= raise {
		t.Fatal("the limit must be raised before hev is started")
	}
	first, _, _ := strings.Cut(s[raise:start], "\n")
	if !strings.Contains(first, "|| true") {
		t.Fatal("a refused raise must not stop the tunnel")
	}
}

func TestFailureAfterStartRemovesWhatWasInstalled(t *testing.T) {
	s := mustScript(t, nil)
	_, after, _ := strings.Cut(s, "fail()")
	fail, _, _ := strings.Cut(after, "\n}")
	wantIn(t, fail, "cleanup")
	wantIn(t, fail, `"$ERR"`)
}

func TestPathsAreQuotedAgainstSpacesAndQuotes(t *testing.T) {
	s := mustScript(t, func(sp *MacTunSupervisorSpec) { sp.HevExecutable = "/Applications/My App/it's/hev" })
	wantIn(t, s, `'/Applications/My App/it'\''s/hev'`)
}

func TestInterfaceNameThatIsNotUtunIsRejected(t *testing.T) {
	for _, name := range []string{"skipi0", "utun", "utun9; rm -rf /", "../utun9", "utun9 ", "utun9\n", ""} {
		if _, err := MacTunSupervisorScript(testSpec(func(sp *MacTunSupervisorSpec) { sp.InterfaceName = name })); err == nil {
			t.Errorf("interface name %q accepted", name)
		}
	}
}

func TestRouteThatIsNotACIDRIsRejected(t *testing.T) {
	for _, route := range []string{"0.0.0.0", "0.0.0.0/1; reboot", "default", "1.2.3.4/33", "::/129", "", "0.0.0.0/1\n", "999.0.0.0/1"} {
		if _, err := MacTunSupervisorScript(testSpec(func(sp *MacTunSupervisorSpec) { sp.Routes = []string{route} })); err == nil {
			t.Errorf("route %q accepted", route)
		}
	}
	if _, err := MacTunSupervisorScript(testSpec(func(sp *MacTunSupervisorSpec) { sp.Routes = nil })); err == nil {
		t.Error("an empty route list accepted")
	}
}

func TestOtherSpecFieldsAreValidated(t *testing.T) {
	bad := map[string]func(*MacTunSupervisorSpec){
		"address":  func(s *MacTunSupervisorSpec) { s.IPv4Address = "172.19.0.256" },
		"address2": func(s *MacTunSupervisorSpec) { s.IPv4Address = "1.2.3.4'; reboot" },
		"mtu low":  func(s *MacTunSupervisorSpec) { s.MTU = 575 },
		"mtu high": func(s *MacTunSupervisorSpec) { s.MTU = 65536 },
		"pid":      func(s *MacTunSupervisorSpec) { s.AppPid = 0 },
		"uid":      func(s *MacTunSupervisorSpec) { s.UserUid = -1 },
	}
	for name, mut := range bad {
		if _, err := MacTunSupervisorScript(testSpec(mut)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestScriptTravelsAsBase64(t *testing.T) {
	script := mustScript(t, nil)
	command := MacPrivilegedShellCommand(script)
	m := regexp.MustCompile(`^echo (\S+) \|`).FindStringSubmatch(command)
	if m == nil {
		t.Fatal(command)
	}
	raw, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil || string(raw) != script {
		t.Fatalf("round trip failed: %v", err)
	}
	if !strings.HasSuffix(command, "&") {
		t.Fatalf("the supervisor keeps running after the prompt returns: %s", command)
	}
	wantIn(t, command, "/usr/bin/base64 -D")
	wantIn(t, command, "/bin/sh")
}

func TestAppleScriptEscapesBackslashesAndQuotes(t *testing.T) {
	want := `do shell script "echo \"a\\b\"" with administrator privileges`
	if got := MacAdminAppleScript(`echo "a\b"`); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	cmd := MacPrivilegedLaunchCommand("true")
	if len(cmd) != 3 || cmd[0] != "/usr/bin/osascript" || cmd[1] != "-e" || cmd[2] != MacAdminAppleScript("true") {
		t.Fatalf("launch command = %v", cmd)
	}
}

func TestDescribeLaunchFailure(t *testing.T) {
	for _, msg := range []string{"execution error: User canceled. (-128)", "boom -128"} {
		if got := DescribeMacLaunchFailure(errors.New(msg)); !strings.Contains(strings.ToLower(got), "administrator") {
			t.Errorf("%q -> %q", msg, got)
		}
	}
	if got := DescribeMacLaunchFailure(errors.New("disk on fire")); got != "Could not start the privileged tunnel: disk on fire" {
		t.Errorf("got %q", got)
	}
	if got := DescribeMacLaunchFailure(errors.New("  ")); got != "Could not start the privileged tunnel: unknown error" {
		t.Errorf("got %q", got)
	}
}

func TestMacIPv4OfTakesTheFirstNonColonAddressWithoutPrefix(t *testing.T) {
	got, err := MacIPv4Of([]string{"fc00::1/64", "198.18.0.1/15"})
	if err != nil || got != "198.18.0.1" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := MacIPv4Of([]string{"fc00::1/64"}); err == nil {
		t.Fatal("no IPv4 address must be an error")
	}
}

func TestValidateMacPlan(t *testing.T) {
	good := func() *MacInterface {
		return &MacInterface{Name: "utun9", MTU: 1500, Addresses: []string{"198.18.0.1/15", "fc00::1/64"},
			Routes: []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}}
	}
	if err := ValidateMacPlan("/h", "/run", good()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() (string, string, *MacInterface){
		"no exe":  func() (string, string, *MacInterface) { return " ", "/run", good() },
		"no dir":  func() (string, string, *MacInterface) { return "/h", "", good() },
		"no mac":  func() (string, string, *MacInterface) { return "/h", "/run", nil },
		"no name": func() (string, string, *MacInterface) { m := good(); m.Name = ""; return "/h", "/run", m },
		"v6 only": func() (string, string, *MacInterface) {
			m := good()
			m.Addresses = []string{"fc00::1/64"}
			return "/h", "/run", m
		},
		"mtu":       func() (string, string, *MacInterface) { m := good(); m.MTU = 0; return "/h", "/run", m },
		"no routes": func() (string, string, *MacInterface) { m := good(); m.Routes = nil; return "/h", "/run", m },
		"bad route": func() (string, string, *MacInterface) {
			m := good()
			m.Routes = []string{"default"}
			return "/h", "/run", m
		},
	}
	for name, c := range cases {
		e, d, m := c()
		if err := ValidateMacPlan(e, d, m); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
