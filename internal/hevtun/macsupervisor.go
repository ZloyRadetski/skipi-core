// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hevtun

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// macOS: hev-socks5-tunnel creates the utun interface itself, and both that and the routes need
// root. Core is never elevated: when the tunnel starts, the user is asked for the administrator
// password once (the standard system prompt of "osascript ... with administrator privileges"), and
// a small supervisor shell script runs as root. The supervisor starts hev, installs the routes and
// removes them again when Core asks for a stop through a file, when hev ends, or when Core itself
// is gone, so a crash never leaves the machine routed into a dead tunnel.
//
// Core's own sockets stay off the tunnel by IP_BOUND_IF (see netbind), so the supervisor needs no
// host routes for the proxy servers.
//
// This file is pure logic with no build tag, so it is tested on every host. The script is POSIX sh
// for macOS whatever system built it.

var (
	macUtunName    = regexp.MustCompile(`^utun[0-9]{1,4}$`)
	macIPv4CIDR    = regexp.MustCompile(`^((?:[0-9]{1,3}\.){3}[0-9]{1,3})/([0-9]{1,2})$`)
	macIPv6CIDR    = regexp.MustCompile(`^([0-9A-Fa-f:]{2,39})/([0-9]{1,3})$`)
	macIPv4Address = regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
)

// MacInterface is the utun interface plan of the session ("macInterface" in the hev block).
type MacInterface struct {
	Name      string   `json:"name"`
	MTU       int      `json:"mtu"`
	Addresses []string `json:"addresses"`
	Routes    []string `json:"routes"`
	// DNS is read so a plan carrying it decodes; the supervisor does not configure DNS yet.
	DNS []string `json:"dns,omitempty"`
}

// MacTunSupervisorSpec is everything the root supervisor needs; the values end up in a script that
// runs with full rights. Paths are POSIX text.
type MacTunSupervisorSpec struct {
	InterfaceName string
	MTU           int
	IPv4Address   string
	Routes        []string
	HevExecutable string
	HevConfig     string
	StopFile      string
	ReadyFile     string
	ErrorFile     string
	AppPid        int64
	UserUid       int
}

// shellQuote is the text as one POSIX shell word: single-quoted, each inner quote becomes quote, backslash, quote, quote.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func validOctets(address string) bool {
	for _, part := range strings.Split(address, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// ValidateMacRoute reports whether route is an IPv4 or IPv6 CIDR.
func ValidateMacRoute(route string) bool {
	if m := macIPv4CIDR.FindStringSubmatch(route); m != nil {
		prefix, _ := strconv.Atoi(m[2])
		return validOctets(m[1]) && prefix >= 0 && prefix <= 32
	}
	if m := macIPv6CIDR.FindStringSubmatch(route); m != nil {
		prefix, _ := strconv.Atoi(m[2])
		return strings.Contains(m[1], ":") && prefix >= 0 && prefix <= 128
	}
	return false
}

func routeCommand(verb, route string) string {
	family := ""
	if strings.Contains(route, ":") {
		family = "-inet6 "
	}
	return "route -n " + verb + " " + family + "-net " + shellQuote(route) + ` -interface "$IFACE"`
}

// MacTunSupervisorScript is the supervisor that runs as root. It is POSIX sh and is handed to the
// shell as base64 text (MacPrivilegedShellCommand), so nothing in it is subject to a second round
// of quoting. An invalid spec is an error: the values are interpolated into a root script.
func MacTunSupervisorScript(spec MacTunSupervisorSpec) (string, error) {
	if !macUtunName.MatchString(spec.InterfaceName) {
		return "", errors.New("the macOS tunnel interface must be named utunN")
	}
	if len(spec.Routes) == 0 {
		return "", errors.New("invalid tunnel route")
	}
	for _, r := range spec.Routes {
		if !ValidateMacRoute(r) {
			return "", errors.New("invalid tunnel route")
		}
	}
	if !macIPv4Address.MatchString(spec.IPv4Address) || !validOctets(spec.IPv4Address) {
		return "", errors.New("invalid tunnel address")
	}
	if spec.MTU < 576 || spec.MTU > 65535 {
		return "", errors.New("invalid tunnel MTU")
	}
	if spec.AppPid <= 0 || spec.UserUid < 0 {
		return "", errors.New("invalid owner")
	}

	var b strings.Builder
	line := func(s string) { b.WriteString(s + "\n") }
	hev := shellQuote(spec.HevExecutable)
	line("IFACE=" + shellQuote(spec.InterfaceName))
	line("STOP=" + shellQuote(spec.StopFile))
	line("READY=" + shellQuote(spec.ReadyFile))
	line("ERR=" + shellQuote(spec.ErrorFile))
	line("APP_PID=" + strconv.FormatInt(spec.AppPid, 10))
	line("HEV_PID=")
	line("cleanup() {")
	line(`  [ -n "$HEV_PID" ] && kill "$HEV_PID" 2>/dev/null`)
	for _, r := range spec.Routes {
		line("  " + routeCommand("delete", r) + " >/dev/null 2>&1")
	}
	line(`  rm -f "$READY"`)
	line("}")
	line("fail() {")
	line(`  printf '%s' "$1" > "$ERR"`)
	line("  chown " + strconv.Itoa(spec.UserUid) + ` "$ERR"`)
	line("  cleanup")
	line("  exit 1")
	line("}")
	line(`trap 'cleanup; rm -f "$STOP"; exit 0' TERM INT HUP`)
	// A packaged helper can lose its executable bit; root restores it instead of failing.
	line("[ -x " + hev + " ] || chmod 755 " + hev + ` || fail "Could not make the tunnel executable"`)
	// hev's own raise asks for an unlimited soft value, which macOS refuses; the default of 256 holds ~100 sessions.
	line("ulimit -n 10240 2>/dev/null || true")
	line(hev + " " + shellQuote(spec.HevConfig) + " </dev/null >/dev/null 2>&1 &")
	line("HEV_PID=$!")
	line("i=0")
	line(`until ifconfig "$IFACE" >/dev/null 2>&1; do`)
	line("  i=$((i + 1))")
	line(`  [ "$i" -gt 100 ] && fail "The tunnel interface did not appear"`)
	line(`  kill -0 "$HEV_PID" 2>/dev/null || fail "The tunnel process stopped before the interface appeared"`)
	line("  sleep 0.1")
	line("done")
	addr := shellQuote(spec.IPv4Address)
	line(`ifconfig "$IFACE" inet ` + addr + " " + addr + " mtu " + strconv.Itoa(spec.MTU) + ` up || fail "Could not configure the tunnel interface"`)
	for _, r := range spec.Routes {
		line(routeCommand("add", r) + ` >/dev/null 2>&1 || fail "Could not add the route ` + r + `"`)
	}
	line(`echo $$ > "$READY"`)
	line("chown " + strconv.Itoa(spec.UserUid) + ` "$READY"`)
	line(`while kill -0 "$HEV_PID" 2>/dev/null && kill -0 "$APP_PID" 2>/dev/null && [ ! -e "$STOP" ]; do sleep 1; done`)
	line("cleanup")
	line(`rm -f "$STOP"`)
	return b.String(), nil
}

// MacPrivilegedShellCommand is the shell command that runs script in the background; the script
// travels as base64.
func MacPrivilegedShellCommand(script string) string {
	return "echo " + base64.StdEncoding.EncodeToString([]byte(script)) + " | /usr/bin/base64 -D | /bin/sh >/dev/null 2>&1 &"
}

// MacAdminAppleScript is the AppleScript that runs shellCommand after the system's administrator
// password prompt.
func MacAdminAppleScript(shellCommand string) string {
	escaped := strings.ReplaceAll(shellCommand, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `do shell script "` + escaped + `" with administrator privileges`
}

// MacPrivilegedLaunchCommand is the osascript command line that runs shellCommand with administrator rights.
func MacPrivilegedLaunchCommand(shellCommand string) []string {
	return []string{"/usr/bin/osascript", "-e", MacAdminAppleScript(shellCommand)}
}

// DescribeMacLaunchFailure turns a failed osascript run into a sentence for the user.
func DescribeMacLaunchFailure(err error) string {
	message := ""
	if err != nil {
		message = err.Error()
	}
	if strings.Contains(message, "User canceled") || strings.Contains(message, "-128") {
		return "Administrator permission was not granted, so TUN mode cannot start"
	}
	if strings.TrimSpace(message) == "" {
		message = "unknown error"
	}
	return "Could not start the privileged tunnel: " + message
}

// MacIPv4Of returns the first address without ':' with its "/prefix" removed, as the supervisor
// takes it from the plan's address list.
func MacIPv4Of(addresses []string) (string, error) {
	for _, a := range addresses {
		if !strings.Contains(a, ":") {
			host, _, _ := strings.Cut(a, "/")
			return host, nil
		}
	}
	return "", errors.New("the macOS tunnel plan has no IPv4 address")
}

// ValidateMacPlan checks the hev block of a session plan on macOS: the executable, the run
// directory and an interface plan with a name, an IPv4 address, a positive MTU and valid routes.
func ValidateMacPlan(executable, runDirectory string, mac *MacInterface) error {
	if strings.TrimSpace(executable) == "" {
		return errors.New("hev.executable must not be blank")
	}
	if strings.TrimSpace(runDirectory) == "" {
		return errors.New("hev.runDirectory must not be blank")
	}
	if mac == nil {
		return errors.New("hev.macInterface is missing")
	}
	if strings.TrimSpace(mac.Name) == "" {
		return errors.New("hev.macInterface.name must not be blank")
	}
	if _, err := MacIPv4Of(mac.Addresses); err != nil {
		return errors.New("hev.macInterface.addresses needs an IPv4 address")
	}
	if mac.MTU <= 0 {
		return errors.New("hev.macInterface.mtu must be positive")
	}
	if len(mac.Routes) == 0 {
		return errors.New("hev.macInterface.routes must not be empty")
	}
	for _, r := range mac.Routes {
		if !ValidateMacRoute(r) {
			return fmt.Errorf("hev.macInterface.routes: invalid route %q", r)
		}
	}
	return nil
}
