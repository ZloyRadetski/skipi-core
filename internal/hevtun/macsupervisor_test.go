// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package hevtun

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ZloyRadetski/skipi-core/internal/hevpayload"
)

// The supervisor, the launch command and the launch-failure text. The script runs as root, so the
// tests pin what it may touch: only its own root-owned state directory is ever written, the user's
// run directory is only looked at, and hev runs from a root-owned copy whose hash Core checked.

const (
	testHev   = "/Applications/SKIPI.app/Contents/Resources/hev/hev-socks5-tunnel"
	testSHA   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testState = "/var/run/skipi-hev.501"
	testStop  = "/Users/test/SKIPI/run/tun-stop"
	testToken = "00112233445566778899aabbccddeeff"
	testYAML  = "tunnel:\n  mtu: 1400\nsocks5:\n  password: 'it''s secret'\n"
)

func testSpec(mut func(*MacTunSupervisorSpec)) MacTunSupervisorSpec {
	s := MacTunSupervisorSpec{
		InterfaceName: "utun9",
		MTU:           1400,
		IPv4Address:   "172.19.0.1",
		Routes:        []string{"0.0.0.0/1", "128.0.0.0/1"},
		HevExecutable: testHev,
		HevSHA256:     testSHA,
		HevConfigYAML: testYAML,
		StateDir:      testState,
		StopFile:      testStop,
		Token:         testToken,
		AppPid:        4242,
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
	wantIn(t, s, `"$HEV" "$CFG"`)
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
	wantIn(t, cleanup, `"$READY"`)
	wantIn(t, cleanup, `"$CFG"`)
}

func TestSessionEndsWhenCoreAsksHevDiesOrCoreIsGone(t *testing.T) {
	s := mustScript(t, nil)
	wantIn(t, s, "APP_PID=4242")
	wantIn(t, s, `kill -0 "$APP_PID"`)
	wantIn(t, s, `kill -0 "$HEV_PID"`)
	wantIn(t, s, `[ -e "$STOP" ]`)
	wantIn(t, s, "trap ")
}

// C1: root never writes, chowns or chmods anything in a directory the user owns. Every write goes
// to a variable rooted in the state directory, and nothing is handed over with chown.
func TestRootWritesOnlyIntoItsOwnStateDirectory(t *testing.T) {
	s := mustScript(t, nil)
	if strings.Contains(s, "chown") {
		t.Fatal("nothing may be handed to the user with chown:\n" + s)
	}
	if strings.Count(s, "/Users/test") != 1 || !strings.Contains(s, "STOP='"+testStop+"'") {
		t.Fatal("the user's run directory may appear only once, as the stop file:\n" + s)
	}
	stateVars := map[string]bool{"READY": true, "ERR": true, "CFG": true, "HEV": true, "EXIT": true, "LOG": true}
	for _, m := range regexp.MustCompile(`>\s*"?\$([A-Z_]+)"?`).FindAllStringSubmatch(s, -1) {
		if !stateVars[m[1]] {
			t.Errorf("redirection into $%s, which is not in the state directory", m[1])
		}
	}
	for _, v := range []string{"READY", "ERR", "CFG", "HEV", "EXIT", "LOG"} {
		wantIn(t, s, v+`="$STATE/`)
	}
	wantIn(t, s, "STATE='"+testState+"'")
}

func TestScriptRefusesToClobberAndUsesAFixedPath(t *testing.T) {
	s := mustScript(t, nil)
	wantIn(t, s, "set -C")
	wantIn(t, s, "PATH=/usr/bin:/bin:/usr/sbin:/sbin")
	// The state directory is rebuilt by root, so no leftover of anyone can sit in it.
	wantIn(t, s, `rm -rf "$STATE"`)
	wantIn(t, s, `mkdir -m 755 "$STATE"`)
}

// C2/C3/C7: the config travels inside the script and is written 0600 into the state directory;
// it never sits in a file the user can swap, and it is removed with the session.
func TestConfigTravelsInsideTheScript(t *testing.T) {
	s := mustScript(t, nil)
	wantIn(t, s, base64.StdEncoding.EncodeToString([]byte(testYAML)))
	if strings.Contains(s, "it''s secret") {
		t.Fatal("the YAML must not be spliced into the script as text")
	}
	wantIn(t, s, "umask 077")
}

// C3: root runs a copy of hev it made itself, and only when the copy has the hash Core checked.
func TestHevRunsFromARootCopyWhoseHashMatches(t *testing.T) {
	s := mustScript(t, nil)
	wantIn(t, s, "HEV_SRC='"+testHev+"'")
	wantIn(t, s, "HEV_SHA='"+testSHA+"'")
	copyAt := strings.Index(s, `cp "$HEV_SRC" "$HEV"`)
	check := strings.Index(s, `shasum -a 256 "$HEV"`)
	run := strings.Index(s, `"$HEV" "$CFG"`)
	if copyAt < 0 || check < 0 || run < 0 || !(copyAt < check && check < run) {
		t.Fatalf("copy %d, check %d, run %d:\n%s", copyAt, check, run, s)
	}
	if strings.Contains(s, "chmod 755 '"+testHev+"'") || strings.Contains(s, `chmod 755 "$HEV_SRC"`) {
		t.Fatal("root must not change the user's file")
	}
}

func TestSupervisorRaisesDescriptorLimitBeforeStartingHev(t *testing.T) {
	s := mustScript(t, nil)
	raise := strings.Index(s, "ulimit -n 10240")
	start := strings.Index(s, `"$HEV" "$CFG"`)
	if raise < 0 || start <= raise {
		t.Fatal("the limit must be raised before hev is started:\n" + s)
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
		"address":       func(s *MacTunSupervisorSpec) { s.IPv4Address = "172.19.0.256" },
		"address2":      func(s *MacTunSupervisorSpec) { s.IPv4Address = "1.2.3.4'; reboot" },
		"mtu low":       func(s *MacTunSupervisorSpec) { s.MTU = 575 },
		"mtu high":      func(s *MacTunSupervisorSpec) { s.MTU = 65536 },
		"pid":           func(s *MacTunSupervisorSpec) { s.AppPid = 0 },
		"relative hev":  func(s *MacTunSupervisorSpec) { s.HevExecutable = "hev/hev-socks5-tunnel" },
		"short hash":    func(s *MacTunSupervisorSpec) { s.HevSHA256 = "abc" },
		"hash not hex":  func(s *MacTunSupervisorSpec) { s.HevSHA256 = strings.Repeat("z", 64) },
		"empty yaml":    func(s *MacTunSupervisorSpec) { s.HevConfigYAML = "" },
		"relative stop": func(s *MacTunSupervisorSpec) { s.StopFile = "run/tun-stop" },
		"token":         func(s *MacTunSupervisorSpec) { s.Token = "x'; reboot" },
		"no token":      func(s *MacTunSupervisorSpec) { s.Token = "" },
		"state rel":     func(s *MacTunSupervisorSpec) { s.StateDir = "var/run/x" },
		"state root":    func(s *MacTunSupervisorSpec) { s.StateDir = "/" },
		"state dotdot":  func(s *MacTunSupervisorSpec) { s.StateDir = "/var/run/../../Users/test" },
	}
	for name, mut := range bad {
		if _, err := MacTunSupervisorScript(testSpec(mut)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestStateDirectoryIsPerUserUnderVarRun(t *testing.T) {
	if got := MacStateDirectory(501); got != "/var/run/skipi-hev.501" {
		t.Fatalf("got %q", got)
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
	if err := ValidateMacPlan("/run", good()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() (string, *MacInterface){
		"no dir":       func() (string, *MacInterface) { return "", good() },
		"relative dir": func() (string, *MacInterface) { return "run", good() },
		"no mac":       func() (string, *MacInterface) { return "/run", nil },
		"no name":      func() (string, *MacInterface) { m := good(); m.Name = ""; return "/run", m },
		"v6 only": func() (string, *MacInterface) {
			m := good()
			m.Addresses = []string{"fc00::1/64"}
			return "/run", m
		},
		"mtu":       func() (string, *MacInterface) { m := good(); m.MTU = 0; return "/run", m },
		"no routes": func() (string, *MacInterface) { m := good(); m.Routes = nil; return "/run", m },
		"bad route": func() (string, *MacInterface) {
			m := good()
			m.Routes = []string{"default"}
			return "/run", m
		},
	}
	for name, c := range cases {
		d, m := c()
		if err := ValidateMacPlan(d, m); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// --- The script itself, run by a real POSIX shell with stand-ins for the macOS tools. ---

type shellRun struct {
	t       *testing.T
	state   string
	userDir string
	stop    string
	tools   string
	log     string
	cmd     *exec.Cmd
	done    chan error
}

// stub writes a tool stand-in that records its arguments in the shared log.
func (r *shellRun) stub(name, body string) {
	r.t.Helper()
	text := "#!/bin/sh\necho \"" + name + " $*\" >> '" + posixPath(r.log) + "'\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(r.tools, name), []byte(text), 0o755); err != nil {
		r.t.Fatal(err)
	}
}

// posixPath is p as the POSIX shell sees it: Git for Windows maps C:\x to /c/x.
func posixPath(p string) string {
	p = filepath.ToSlash(p)
	if len(p) > 2 && p[1] == ':' {
		p = "/" + strings.ToLower(p[:1]) + p[2:]
	}
	return p
}

func skipShellUnlessEnabled(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" && os.Getenv("SKIPI_SHELL_TESTS") == "" {
		// Git for Windows has a POSIX shell, but its process start is slow; opt in.
		t.Skip("set SKIPI_SHELL_TESTS=1 to run the shell supervisor on Windows")
	}
}

func startShellSupervisor(t *testing.T, mut func(*MacTunSupervisorSpec), hevBody string, stopFirst bool) *shellRun {
	t.Helper()
	skipShellUnlessEnabled(t)
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX shell")
	}
	for _, tool := range []string{"sha256sum", "base64", "cp", "rm", "mkdir", "chmod", "cut", "sleep"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	root := t.TempDir()
	r := &shellRun{t: t, state: filepath.Join(root, "state"), userDir: filepath.Join(root, "user"),
		tools: filepath.Join(root, "tools"), log: filepath.Join(root, "tools.log")}
	r.stop = filepath.Join(r.userDir, "tun-stop")
	for _, d := range []string{r.userDir, r.tools} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// What an attacker could have planted where the old supervisor wrote: it must stay untouched.
	for _, f := range []string{"tun-ready", "tun-error", "tun-hev.yaml"} {
		if err := os.WriteFile(filepath.Join(r.userDir, f), []byte("victim"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	hev := filepath.Join(root, "bundle", "hev-socks5-tunnel")
	if err := os.MkdirAll(filepath.Dir(hev), 0o755); err != nil {
		t.Fatal(err)
	}
	if hevBody == "" {
		hevBody = "trap 'exit 0' TERM\nwhile :; do sleep 1; done"
	}
	if err := os.WriteFile(hev, []byte("#!/bin/sh\n"+hevBody+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum, err := hevpayload.File{Data: mustRead(t, hev)}.SHA256(), error(nil)
	if err != nil {
		t.Fatal(err)
	}
	real := func(name string) string { p, _ := exec.LookPath(name); return posixPath(p) }
	r.stub("ifconfig", "exit 0")
	r.stub("route", "exit 0")
	r.stub("shasum", `shift 2; "`+real("sha256sum")+`" "$@"`)
	r.stub("base64", `"`+real("base64")+`" -d`)

	spec := testSpec(func(s *MacTunSupervisorSpec) {
		s.HevExecutable = posixPath(hev)
		s.HevSHA256 = sum
		s.StateDir = posixPath(r.state)
		s.StopFile = posixPath(r.stop)
		s.AppPid = 1 // replaced below: the shell's own pid stands in for Core
	})
	if mut != nil {
		mut(&spec)
	}
	script, err := MacTunSupervisorScript(spec)
	if err != nil {
		t.Fatal(err)
	}
	script = strings.Replace(script, "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "PATH='"+posixPath(r.tools)+"':$PATH", 1)
	script = strings.Replace(script, "APP_PID=1\n", "APP_PID=$$\n", 1)
	if stopFirst {
		if err := os.WriteFile(r.stop, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r.cmd = exec.Command(sh, "-c", script)
	r.done = make(chan error, 1)
	if err := r.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { r.done <- r.cmd.Wait() }()
	t.Cleanup(func() {
		_ = os.WriteFile(r.stop, nil, 0o644)
		select {
		case <-r.done:
		case <-time.After(10 * time.Second):
			_ = r.cmd.Process.Kill()
		}
	})
	return r
}

func (r *shellRun) read(name string) string {
	b, err := os.ReadFile(filepath.Join(r.state, name))
	if err != nil {
		return ""
	}
	return string(b)
}

func (r *shellRun) waitFor(what string, ok func() bool) {
	r.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(r.log)
			r.t.Fatalf("timed out waiting for %s; tools:\n%s", what, log)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (r *shellRun) exited() bool {
	select {
	case err := <-r.done:
		r.done <- err
		return true
	default:
		return false
	}
}

func (r *shellRun) userFilesUntouched() {
	r.t.Helper()
	entries, _ := os.ReadDir(r.userDir)
	for _, e := range entries {
		if e.Name() == "tun-stop" {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(r.userDir, e.Name()))
		if string(b) != "victim" {
			r.t.Errorf("root changed %s in the user's directory: %q", e.Name(), b)
		}
	}
	if len(entries) > 4 {
		r.t.Errorf("root created files in the user's directory: %v", entries)
	}
}

func TestShellSupervisorRunsARootCopyAndCleansUpOnStop(t *testing.T) {
	r := startShellSupervisor(t, nil, "", false)
	r.waitFor("ready", func() bool { return r.read("tun-ready") != "" || r.read("tun-error") != "" })
	if e := r.read("tun-error"); e != "" {
		t.Fatalf("supervisor failed: %s", e)
	}
	ready := strings.Fields(r.read("tun-ready"))
	if len(ready) != 2 || ready[1] != testToken {
		t.Fatalf("ready marker = %q, want pid and token", r.read("tun-ready"))
	}
	if got := r.read("hev.yaml"); got != testYAML {
		t.Fatalf("config in the state directory = %q", got)
	}
	if r.read("hev-socks5-tunnel") == "" {
		t.Fatal("hev must run from the copy in the state directory")
	}
	r.userFilesUntouched()

	if err := os.WriteFile(r.stop, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	r.waitFor("exit", r.exited)
	for _, gone := range []string{"tun-ready", "hev.yaml", "hev-socks5-tunnel"} {
		if _, err := os.Stat(filepath.Join(r.state, gone)); err == nil {
			t.Errorf("%s survived the stop", gone)
		}
	}
	if got := strings.TrimSpace(r.read("tun-exit")); got != testToken {
		t.Errorf("exit marker = %q, want the token", got)
	}
	log, _ := os.ReadFile(r.log)
	if !strings.Contains(string(log), "route -n delete -net 0.0.0.0/1") {
		t.Errorf("routes were not removed:\n%s", log)
	}
	r.userFilesUntouched()
}

func TestShellSupervisorRefusesAHevThatChangedAfterTheCheck(t *testing.T) {
	r := startShellSupervisor(t, func(s *MacTunSupervisorSpec) { s.HevSHA256 = testSHA }, "", false)
	r.waitFor("exit", r.exited)
	errText := r.read("tun-error")
	if !strings.HasPrefix(errText, testToken+"\n") || !strings.Contains(errText, "changed") {
		t.Fatalf("error marker = %q", errText)
	}
	log, _ := os.ReadFile(r.log)
	if strings.Contains(string(log), "route -n add") || strings.Contains(string(log), "ifconfig") {
		t.Fatalf("nothing may be configured with an unchecked hev:\n%s", log)
	}
	r.userFilesUntouched()
}

// H2: the user cancelled while the password prompt was up, and the supervisor still got started.
func TestShellSupervisorThatFindsAStopRequestDoesNothing(t *testing.T) {
	r := startShellSupervisor(t, nil, "", true)
	r.waitFor("exit", r.exited)
	log, _ := os.ReadFile(r.log)
	if strings.Contains(string(log), "route -n add") || strings.Contains(string(log), "ifconfig") {
		t.Fatalf("a cancelled start must not configure anything:\n%s", log)
	}
	if got := strings.TrimSpace(r.read("tun-exit")); got != testToken {
		t.Errorf("exit marker = %q", got)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
