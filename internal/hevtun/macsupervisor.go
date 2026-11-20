// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hevtun

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path"
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
// Root never writes where the user can: every file it creates is in its own state directory under
// /var/run, which it rebuilds for each session. The user's run directory is only looked at for the
// stop request. hev runs from a copy root made, checked against the hash Core took, and the config
// travels inside the script, so nothing the user can swap is ever run or read by root.
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
	macHexHash     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	macToken       = regexp.MustCompile(`^[0-9a-f]{16,64}$`)
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
	// HevExecutable is the shipped hev; root copies it into StateDir and runs the copy only when
	// it has HevSHA256, the hash Core took of it.
	HevExecutable string
	HevSHA256     string
	// HevConfigYAML travels inside the script and is written 0600 into StateDir.
	HevConfigYAML string
	// StateDir is the root-owned directory the supervisor rebuilds and writes all its files into.
	StateDir string
	// StopFile is Core's stop request in the user's run directory; root only tests that it exists.
	StopFile string
	// Token marks this session's markers, so leftovers of another session are never taken for them.
	Token  string
	AppPid int64
}

// MacStateDirectory is the root-owned directory of the supervisor of user uid.
func MacStateDirectory(uid int) string { return "/var/run/skipi-hev." + strconv.Itoa(uid) }

// shellQuote is the text as one POSIX shell word: single-quoted, each inner quote becomes quote, backslash, quote, quote.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// cleanAbsolute reports whether p is an absolute POSIX path in its shortest form, other than "/".
func cleanAbsolute(p string) bool {
	return strings.HasPrefix(p, "/") && p != "/" && path.Clean(p) == p && !strings.ContainsAny(p, "\x00\n")
}

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

func validateSupervisorSpec(spec MacTunSupervisorSpec) error {
	if !macUtunName.MatchString(spec.InterfaceName) {
		return errors.New("the macOS tunnel interface must be named utunN")
	}
	if len(spec.Routes) == 0 {
		return errors.New("invalid tunnel route")
	}
	for _, r := range spec.Routes {
		if !ValidateMacRoute(r) {
			return errors.New("invalid tunnel route")
		}
	}
	if !macIPv4Address.MatchString(spec.IPv4Address) || !validOctets(spec.IPv4Address) {
		return errors.New("invalid tunnel address")
	}
	if spec.MTU < 576 || spec.MTU > 65535 {
		return errors.New("invalid tunnel MTU")
	}
	if spec.AppPid <= 0 {
		return errors.New("invalid owner")
	}
	if !cleanAbsolute(spec.HevExecutable) {
		return errors.New("the tunnel executable must be an absolute path")
	}
	if !macHexHash.MatchString(spec.HevSHA256) {
		return errors.New("invalid tunnel executable hash")
	}
	if spec.HevConfigYAML == "" {
		return errors.New("the tunnel config is empty")
	}
	if !cleanAbsolute(spec.StateDir) || !cleanAbsolute(spec.StopFile) {
		return errors.New("the tunnel state and stop paths must be absolute")
	}
	if !macToken.MatchString(spec.Token) {
		return errors.New("invalid tunnel session token")
	}
	return nil
}

// MacTunSupervisorScript is the supervisor that runs as root. It is POSIX sh and is handed to the
// shell as base64 text (MacPrivilegedShellCommand), so nothing in it is subject to a second round
// of quoting. An invalid spec is an error: the values are interpolated into a root script.
//
// Its markers in StateDir, readable by Core: tun-ready holds "<supervisor pid> <token>", tun-error
// "<token>" and the reason on the next line, tun-exit "<token>" once it cleaned up and is leaving.
func MacTunSupervisorScript(spec MacTunSupervisorSpec) (string, error) {
	if err := validateSupervisorSpec(spec); err != nil {
		return "", err
	}

	var b strings.Builder
	line := func(s string) { b.WriteString(s + "\n") }
	// Never write through an existing name, and never take a tool from anywhere but the system.
	line("set -C")
	line("umask 022")
	line("PATH=/usr/bin:/bin:/usr/sbin:/sbin")
	line("export PATH")
	line("IFACE=" + shellQuote(spec.InterfaceName))
	line("STATE=" + shellQuote(spec.StateDir))
	line("STOP=" + shellQuote(spec.StopFile))
	line("TOKEN=" + shellQuote(spec.Token))
	line("HEV_SRC=" + shellQuote(spec.HevExecutable))
	line("HEV_SHA=" + shellQuote(spec.HevSHA256))
	line(`READY="$STATE/tun-ready"`)
	line(`ERR="$STATE/tun-error"`)
	line(`EXIT="$STATE/tun-exit"`)
	line(`CFG="$STATE/hev.yaml"`)
	line(`HEV="$STATE/hev-socks5-tunnel"`)
	line(`LOG="$STATE/hev.log"`)
	line("APP_PID=" + strconv.FormatInt(spec.AppPid, 10))
	line("HEV_PID=")
	line("ROUTED=")
	line("cleanup() {")
	line(`  [ -n "$HEV_PID" ] && kill "$HEV_PID" 2>/dev/null`)
	line(`  if [ -n "$ROUTED" ]; then`)
	for _, r := range spec.Routes {
		line("    " + routeCommand("delete", r) + " >/dev/null 2>&1")
	}
	line("  fi")
	line(`  rm -f "$READY" "$CFG" "$HEV" "$EXIT"`)
	line(`  printf '%s\n' "$TOKEN" > "$EXIT"`)
	line("}")
	line("fail() {")
	line(`  rm -f "$ERR"`)
	line(`  printf '%s\n%s\n' "$TOKEN" "$1" > "$ERR"`)
	line("  cleanup")
	line("  exit 1")
	line("}")
	line(`stopped() { [ -e "$STOP" ] || ! kill -0 "$APP_PID" 2>/dev/null; }`)
	line(`trap 'cleanup; exit 0' TERM INT HUP`)
	// /var/run is root's alone, so nothing on the way to the state directory can be a user's link,
	// and rebuilding it leaves no leftover of anyone inside.
	line(`rm -rf "$STATE" && mkdir -m 755 "$STATE" || exit 1`)
	// A stop request already here means the start was cancelled while the password prompt was up.
	line(`if stopped; then cleanup; exit 0; fi`)
	line(`cp "$HEV_SRC" "$HEV" || fail "Could not copy the tunnel executable"`)
	line(`[ "$(shasum -a 256 "$HEV" | cut -d ' ' -f 1)" = "$HEV_SHA" ] || fail "The tunnel executable changed after it was checked"`)
	line(`chmod 755 "$HEV" || fail "Could not make the tunnel executable"`)
	line(`(umask 077; echo ` + base64.StdEncoding.EncodeToString([]byte(spec.HevConfigYAML)) + ` | base64 -D > "$CFG") || fail "Could not write the tunnel config"`)
	// hev's own raise asks for an unlimited soft value, which macOS refuses; the default of 256 holds ~100 sessions.
	line("ulimit -n 10240 2>/dev/null || true")
	line(`"$HEV" "$CFG" </dev/null > "$LOG" 2>&1 &`)
	line("HEV_PID=$!")
	line("i=0")
	line(`until ifconfig "$IFACE" >/dev/null 2>&1; do`)
	line("  i=$((i + 1))")
	line(`  [ "$i" -gt 100 ] && fail "The tunnel interface did not appear"`)
	line(`  kill -0 "$HEV_PID" 2>/dev/null || fail "The tunnel process stopped before the interface appeared"`)
	line(`  if stopped; then cleanup; exit 0; fi`)
	line("  sleep 0.1")
	line("done")
	addr := shellQuote(spec.IPv4Address)
	line(`ifconfig "$IFACE" inet ` + addr + " " + addr + " mtu " + strconv.Itoa(spec.MTU) + ` up || fail "Could not configure the tunnel interface"`)
	line("ROUTED=1")
	for _, r := range spec.Routes {
		line(routeCommand("add", r) + ` >/dev/null 2>&1 || fail "Could not add the route ` + r + `"`)
	}
	line(`if stopped; then cleanup; exit 0; fi`)
	line(`printf '%s %s\n' "$$" "$TOKEN" > "$READY"`)
	line(`while kill -0 "$HEV_PID" 2>/dev/null && ! stopped; do sleep 1; done`)
	line("cleanup")
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

// ValidateMacPlan checks the hev block of a session plan on macOS: an absolute executable, an
// absolute run directory and an interface plan with a name, an IPv4 address, a positive MTU and
// valid routes.
func ValidateMacPlan(executable, runDirectory string, mac *MacInterface) error {
	if strings.TrimSpace(executable) == "" {
		return errors.New("hev.executable must not be blank")
	}
	if !cleanAbsolute(executable) {
		return errors.New("hev.executable must be an absolute path")
	}
	if strings.TrimSpace(runDirectory) == "" {
		return errors.New("hev.runDirectory must not be blank")
	}
	if !cleanAbsolute(runDirectory) {
		return errors.New("hev.runDirectory must be an absolute path")
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
