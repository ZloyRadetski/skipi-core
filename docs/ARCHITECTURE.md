# Architecture

SKIPI Core is a thin facade over Xray-core and AmneziaWG. The same Go module is shipped two ways:

- Android: `gomobile bind` of the **root package** (`.`), Java package `app.skipi.core.skipicore`.
- Desktop: a c-shared library built from `cmd/skipicore-desktop`, which exports C functions through
  `desktop/bridge` and imports the root package.

## Layout

```
skipicore.go          package doc and the wrapper version
controller.go         CoreController: lifecycle state machine (StartLoop, StopLoop, ForceStop, ...)
controller_stats.go   CoreController traffic-stat methods
session.go            session API: StartSession plan, State, StateListener, AmneziaWG readiness wait
callbacks.go          interfaces the host implements: CoreCallbackHandler, ProcessFinder, SocketProtector
env.go                InitCoreEnv, CoreVersion, CheckVersionX, ReconcileBrowserDialer, env helpers
probes.go             MeasureOutboundDelay/Download, CancelOutboundDownload, FastSelectBestOutbound
certs.go              FetchTlsCertSha256, FetchQuicCertSha256
memory.go             MemoryStats, ReadMemoryStats, ForceFreeMemory
connection_log.go     ConnectionLogEntry and the controller's connection-log methods
amneziawg.go          AmneziaWG exported API and the process-wide runner
amneziawg_settings.go methods of AmneziaWgSettings (validation, IPC config)
amneziawg_runner.go   AmneziaWgRunner (netstack tunnel + SOCKS listener)
amneziawg_socks.go    the runner's SOCKS5 handlers
process_finder_*.go   RegisterProcessFinder: Android implementation / no-op elsewhere (build tags)

internal/hevtun       HEV TUN (hev-socks5-tunnel): cgo on Android and Linux (build/hev static libs), supervised process on Windows, osascript-elevated supervisor on macOS, stub elsewhere
internal/lifecycle    bounded stop (RunBounded), abandoned counter, shared stop operation
internal/xraylog      console log writer registered with Xray
internal/connlog      connection log implementation
internal/trafficstats traffic-counter snapshot and encodings
internal/probe        delay / download / fast-select implementations
internal/certfetch    TLS and QUIC certificate fingerprints
internal/memstats     runtime/metrics reading
internal/amneziawg    value parsing/validation, endpoint resolution, SOCKS5 wire helpers, outbound rewrite
internal/runtimetuning GC percent and soft memory limit (mobile only), GOMAXPROCS, startup GC pause
internal/assets       Xray asset reader (filesystem on desktop, APK fallback on Android/iOS)

desktop/              bridge (C exports), netbind, nmtun, notify, tunhost, include (C header)
cmd/skipicore-desktop c-shared entry point
third_party/          hev-socks5-tunnel submodule + patches; scripts/ builds it and the AAR
testdata/             public_api.golden, the pinned exported API
```

## The gomobile rule

`gomobile bind` only generates bindings for what is **defined in the bound package**. Therefore:

- Every exported function, method and type lives in the root package. Never use a type alias to an
  `internal/` type and never mention an `internal/` type in an exported signature.
- Types that carry methods (`CoreController`, `AmneziaWgSettings`, `AmneziaWgRunner`) stay in the
  root, because Go methods must be declared next to their type. Their bodies may delegate to
  `internal/`; only machinery that does not need the bound types moves there.
- Plain data types (`MemoryStats`, `ConnectionLogEntry`) stay defined in the root; the internal
  implementation has a twin with identical fields, and a `var _ = Type(internal.Twin{})`
  conversion fails to compile if the two drift apart.
- Exported API is JSON strings and primitives wherever possible: new fields belong in the JSON, not
  in a new bound type.

`api_test.go` enforces this. `TestPublicAPIMatchesGolden` renders every exported declaration of the
root package (all build tags) and compares it with `testdata/public_api.golden`.
`TestPublicAPIDoesNotExposeInternalTypes` fails when an exported signature references `internal/`.

## Adding an exported function

1. Implement it in the matching `internal/<pkg>` (or add a package).
2. Add a thin exported wrapper in the matching root file (or a new root file named after the concern).
3. Review the API change and run `go test -run TestPublicAPIMatchesGolden -update .`; commit the
   updated `testdata/public_api.golden` together with the change. Never regenerate it for a
   refactor that is meant to leave the API alone.
4. If the desktop app needs it, add a C export in `desktop/bridge` and declare it in
   `desktop/include/skipicore_desktop.h`.
5. Keep Android's reflection users in mind: `Skipicore.newCoreController`, `initCoreEnv`,
   `coreVersion`, `measureOutboundDelay`, `readMemoryStats`, `forceFreeMemory`,
   `setAmneziaWgSocketProtector`, and the `CoreController`, `CoreCallbackHandler` and
   `SocketProtector` types must keep their names and signatures.

## Tunnel session

`StartSession(planJSON, tunFd)` makes the controller the whole tunnel session, so hosts only call
start and stop. The plan is `{"xrayConfig": "<json>", "amneziaWg": {"config": "<json>", "socksPort": N}
(optional), "connectionLog": bool, "hev": {"configYaml": "<yaml>", "tunFd": N, "executable": "<path>", "runDirectory": "<dir>",
"macInterface": {"name": "utun9", "mtu": 1500, "addresses": ["198.18.0.1/15", "fc00::1/64"],
"routes": ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"], "dns": [...]}} (optional)}`; unknown
fields are ignored. `tunFd` must be positive where hev runs in process (Android, Linux) and is
ignored on Windows and macOS; `executable` is used on Windows and macOS. On macOS `executable`,
`runDirectory` (marker files and the generated hev config, created 0700) and `macInterface` are
required and validated before anything starts: a non-blank name, an IPv4 address, `mtu` > 0 and
only valid IPv4/IPv6 CIDR routes (`dns` is accepted but not configured yet).

1. With `amneziaWg`: start it, then poll a TCP dial to `127.0.0.1:socksPort` until it accepts
   (`awgReadyTimeout`, 8 s). `AmneziaWgRunner.Start` binds the listener before it returns, so the
   first dial normally succeeds; the poll keeps the contract independent of that. Not ready in time:
   AmneziaWG is stopped (bounded) and the error names the port and the timeout.
2. Apply `connectionLog`, then the ordinary `StartLoop` path. An Xray failure stops AmneziaWG.
   With `hev`, HEV TUN starts after Xray and Core waits for its readiness (`hevReadyTimeout`, 5 s; on macOS the supervisor's own 30 s budget when longer).
   Not ready or failed: HEV TUN, Xray and AmneziaWG are stopped in reverse.
   Stop order is HEV TUN, Xray, AmneziaWG, each bounded; a hung HEV TUN stop counts as abandoned.
   `QueryTunnelStats` returns hev's packet and byte counters as JSON (desktop:
   `SkipiCoreDesktopQueryTunnelStats`; zeros on Windows).

### HEV TUN per platform

HEV TUN is the TUN implementation everywhere; what differs is how Core runs it
(`internal/hevtun`, selected by build tags, behind the `hevTun` seam):

| Platform | How | TUN | Readiness | Stats |
|---|---|---|---|---|
| Android | static libs linked in process (cgo, `scripts/build-hev-android.sh`) | descriptor from the VpnService (`tunFd`) | ready callback (patch) | hev counters |
| Linux amd64 | static libs linked in process (cgo, `scripts/build-hev-linux.sh`, `build/hev/linux-amd64`) | descriptor Core's desktop TUN opened (`tunFd`) | ready callback (patch) | hev counters |
| Windows | supervised child process: `<executable> <temp config>`, run from the executable's directory (wintun.dll and the MSYS DLLs sit there); output goes to Core's log | hev creates the Wintun adapter itself, `tunFd` ignored | no callback across processes: Start waits a 150 ms grace and an earlier exit is a failure (first 4 KB of output in the error); WaitReady only reports whether the process is alive | zeros (counters live in another process) |
| macOS | supervised privileged process (osascript administrator prompt), run by Core: a root `sh` supervisor starts the hev executable the app ships, installs the routes and removes them again on a stop request, hev exit or Core exit (`macsupervisor.go`, `macflow.go`, `hevtun_darwin.go`) | hev creates the utun interface itself, `tunFd` ignored; Core installs address, MTU and routes from `macInterface` | markers in the root-owned `/var/run/skipi-hev.<uid>`, each carrying the session token: `tun-ready` (supervisor pid), `tun-error` (reason), `tun-exit` (cleaned up), up to 30 s after the prompt is answered; `Running` is this session's ready marker naming a live process and no pending `tun-stop` | zeros (counters live in the root process) |

macOS privilege boundary: root writes only into its state directory, which it rebuilds under
`/var/run` for every session (`set -C`, fixed `PATH`, no `chown`). The user's `runDirectory` holds
only `tun-stop`, Core's stop request, which root tests and never touches. Root copies the shipped
hev into the state directory and runs the copy only when its SHA-256 matches the hash Core took at
Start; the config travels base64 inside the script and is written there 0600, and the copy, the
config and the ready marker are removed at the end. A Stop while the administrator prompt is up
ends osascript and leaves `tun-stop`, so a supervisor that still got started leaves before it
configures anything.

hev config policy (every target): `SanitizeConfig` lets through only the known keys of `tunnel`,
`socks5`, `mapdns` and `misc` as single values and refuses everything else, among them
`post-up-script`, `pre-down-script` and `pid-file`. `misc.log-file` is kept where hev runs in
process and dropped in the process modes (Windows, macOS), where hev has more rights than the app.

Core builds and ships the process-mode executables itself, as release assets of every Core
version (`build-desktop.yml`): `hev-macos-<arch>.tar.gz` from `scripts/build-hev-mac.sh` (hev's
default build, no in-process patch) and `hev-windows-x64.zip` from `scripts/package-hev-windows.sh`
(the official hev 2.19.3 archive, pinned by SHA-256, plus the vendored `msys-gcc_s-seh-1.dll`). The
app only downloads them, so the hev version and its checksums live in this repository.

Windows runs only an executable given as an absolute path inside the Core library's own directory
(links resolved), keeps it in a kill-on-close job object so it ends with Core even after a crash,
and writes the config into a new temp file whose protected DACL admits only SYSTEM, Administrators
and the owner. Stop terminates the process and waits up to 5 s; a process still alive stays known
so a later Stop or ForceStop can end it. The config is deleted when the process is gone.
Builds without cgo (and other OSes) get the stub that returns "HEV TUN is not built into this Core
on <GOOS>". `scripts/build-hev-linux.sh` builds a patched copy of the submodule with `make static`
(`-fPIC`) and never touches `build/hev/android`; the Android script clears all of `build/hev`.
3. The session owns the runner: `StopLoop`, `StopLoopWithTimeout` and `ForceStop` stop it too (a
   timed-out stop counts as abandoned). A plain `StartLoop` never makes `StopLoop` touch AmneziaWG.
4. `ForceStop` during the AmneziaWG phase bumps the same generation counter as for `StartLoop`, so
   the readiness wait ends within one poll and the start returns an error.

`State()` returns `SessionIdle/Starting/Running/Stopping` and only takes the short lifecycle lock.
`SetStateListener` registers a `StateListener` that is called synchronously on every transition
(failure message or stop error as `detail`), after `c.mu` is released; a panic in it is recovered.
Desktop exposes `SkipiCoreDesktopStartSession`, `SkipiCoreDesktopSessionState` (-1: unknown handle)
and `SkipiCoreDesktopQueryTunnelStats`.

## Test seams

`createCoreInstance`, `startCoreInstance`, `awgStop`, `startAmneziaWgFn`, `awgReadyTimeout`, `hevTun`, `hevReadyTimeout`,
`defaultStopTimeout` and `forceStopTimeout`
(controller.go, amneziawg.go) are package-level variables so `stop_timeout_test.go` can simulate a
hanging Xray or AmneziaWG close. Tests that touch unexported root state live in the root package;
tests of an implementation live next to it in `internal/`.
