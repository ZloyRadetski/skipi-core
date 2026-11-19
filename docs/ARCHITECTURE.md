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

internal/lifecycle    bounded stop (RunBounded), abandoned counter, shared stop operation
internal/xraylog      console log writer registered with Xray
internal/connlog      connection log implementation
internal/trafficstats traffic-counter snapshot and encodings
internal/probe        delay / download / fast-select implementations
internal/certfetch    TLS and QUIC certificate fingerprints
internal/memstats     runtime/metrics reading
internal/amneziawg    value parsing/validation, endpoint resolution, SOCKS5 wire helpers, outbound rewrite
internal/runtimetuning GC percent, memory limit, GOMAXPROCS, startup GC pause
internal/assets       Xray asset reader (filesystem on desktop, APK fallback on Android/iOS)

desktop/              bridge (C exports), netbind, nmtun, notify, tunhost, include (C header)
cmd/skipicore-desktop c-shared entry point
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

## Test seams

`createCoreInstance`, `startCoreInstance`, `awgStop`, `defaultStopTimeout` and `forceStopTimeout`
(controller.go, amneziawg.go) are package-level variables so `stop_timeout_test.go` can simulate a
hanging Xray or AmneziaWG close. Tests that touch unexported root state live in the root package;
tests of an implementation live next to it in `internal/`.
