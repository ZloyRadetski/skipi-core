package skipicore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

type dummyCallbackHandler struct{}

func (d *dummyCallbackHandler) Startup() int64 {
	return 0
}

func (d *dummyCallbackHandler) Shutdown() int64 {
	return 0
}

func (d *dummyCallbackHandler) OnEmitStatus(code int64, message string) int64 {
	return 0
}

type dummyProcessFinder struct{}

func (d *dummyProcessFinder) FindProcessByConnection(network, srcIP string, srcPort int, destIP string, destPort int) int {
	return 10001
}

func TestCoreVersion(t *testing.T) {
	v := CoreVersion()
	if v == "" {
		t.Fatal("expected non-empty core version")
	}
	t.Logf("Core version: %s", v)
}

func TestCheckVersionX(t *testing.T) {
	v := CheckVersionX()
	if v == "" {
		t.Fatal("expected non-empty CheckVersionX")
	}
	t.Logf("CheckVersionX: %s", v)
}

func TestInitCoreEnv(t *testing.T) {
	InitCoreEnv("/tmp/assets", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
}

func TestReconcileBrowserDialer(t *testing.T) {
	ReconcileBrowserDialer("127.0.0.1:1080")
	ReconcileBrowserDialer("")
}

func TestStartAndStopLoop(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	configJSON := fmt.Sprintf(`{
		"log": {
			"loglevel": "none"
		},
		"inbounds": [
			{
				"port": %d,
				"listen": "127.0.0.1",
				"protocol": "socks",
				"settings": {
					"auth": "noauth",
					"udp": false
				}
			}
		],
		"outbounds": [
			{
				"protocol": "freedom",
				"tag": "direct"
			}
		]
	}`, port)

	ctrl := NewCoreController(&dummyCallbackHandler{})
	ctrl.RegisterProcessFinder(&dummyProcessFinder{})

	if err := ctrl.StartLoop(configJSON, 0); err != nil {
		t.Fatalf("StartLoop failed: %v", err)
	}

	if !ctrl.IsRunning() {
		t.Fatal("expected controller to be running")
	}

	// Test active connection delay measurement
	delay, err := ctrl.MeasureDelay(ts.URL)
	if err != nil {
		t.Fatalf("MeasureDelay failed on running instance: %v", err)
	}
	if delay < 0 {
		t.Fatalf("expected non-negative delay, got %d", delay)
	}
	t.Logf("Active instance MeasureDelay: %d ms", delay)

	// Test querying traffic stats
	_ = ctrl.QueryAllOutboundTrafficStats()

	if err := ctrl.StopLoop(); err != nil {
		t.Fatalf("StopLoop failed: %v", err)
	}

	if ctrl.IsRunning() {
		t.Fatal("expected controller to not be running")
	}
}

func TestTrafficStatsSnapshotFromTotalsSeparatesDirectionsAndTags(t *testing.T) {
	snapshot := trafficStatsSnapshotFromTotals(map[string]int64{
		"inbound>>>socks-in>>>traffic>>>uplink":       11,
		"inbound>>>socks-in>>>traffic>>>downlink":     22,
		"outbound>>>proxy>>>traffic>>>uplink":         33,
		"outbound>>>proxy>>>traffic>>>downlink":       44,
		"outbound>>>direct>>>traffic>>>uplink":        55,
		"not-a-traffic-counter":                       99,
		"inbound>>>missing-direction>>>traffic>>>bad": 77,
	})

	if got := snapshot.Inbound["socks-in"]; got != (trafficStatsBytes{Uplink: 11, Downlink: 22}) {
		t.Fatalf("unexpected inbound stats: %+v", got)
	}
	if got := snapshot.Outbound["proxy"]; got != (trafficStatsBytes{Uplink: 33, Downlink: 44}) {
		t.Fatalf("unexpected proxy stats: %+v", got)
	}
	if got := snapshot.Outbound["direct"]; got != (trafficStatsBytes{Uplink: 55}) {
		t.Fatalf("unexpected direct stats: %+v", got)
	}
	if _, found := snapshot.Inbound["missing-direction"]; found {
		t.Fatal("invalid traffic counter must not appear in the snapshot")
	}

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("snapshot must be JSON encodable: %v", err)
	}
	if !strings.Contains(string(encoded), `"inbound"`) || !strings.Contains(string(encoded), `"outbound"`) {
		t.Fatalf("snapshot JSON must retain both directions: %s", encoded)
	}
}

func TestQueryTrafficStatsReturnsStructuredEmptySnapshotWhenStopped(t *testing.T) {
	controller := NewCoreController(nil)
	if got := controller.QueryTrafficStats(); got != emptyTrafficStatsSnapshotJSON {
		t.Fatalf("unexpected stopped-core stats snapshot: %s", got)
	}
}

func TestMeasureOutboundDelay(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	configJSON := `{
		"log": {
			"loglevel": "none"
		},
		"outbounds": [
			{
				"protocol": "freedom",
				"tag": "direct"
			}
		]
	}`

	delay, err := MeasureOutboundDelay(configJSON, ts.URL)
	if err != nil {
		t.Fatalf("MeasureOutboundDelay failed: %v", err)
	}
	if delay < 0 {
		t.Fatalf("expected non-negative delay, got %d", delay)
	}
	t.Logf("Measured outbound delay to local test server: %d ms", delay)
}

func TestFetchTlsCertSha256(t *testing.T) {
	// Generate self-signed certificate for test TLS server
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	ts.StartTLS()
	defer ts.Close()

	port := ts.Listener.Addr().(*net.TCPAddr).Port

	req := certSha256Request{
		Address:   "127.0.0.1",
		Port:      port,
		TimeoutMs: 2000,
	}
	reqData, _ := json.Marshal(req)
	resJSON := FetchTlsCertSha256(string(reqData))

	var res certSha256Result
	if err := json.Unmarshal([]byte(resJSON), &res); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	if res.Error != "" {
		t.Fatalf("unexpected error: %s", res.Error)
	}
	if len(res.Sha256) != 64 {
		t.Fatalf("expected 64-char sha256, got: %s", res.Sha256)
	}
	t.Logf("Fetched TLS cert SHA256: %s", res.Sha256)
}

func TestMemoryStats(t *testing.T) {
	ForceFreeMemory()

	statsJSON := ReadMemoryStats()
	if statsJSON == "" {
		t.Fatal("ReadMemoryStats returned empty string")
	}

	var stats MemoryStats
	if err := json.Unmarshal([]byte(statsJSON), &stats); err != nil {
		t.Fatalf("failed to unmarshal MemoryStats: %v", err)
	}

	if stats.AllocBytes <= 0 {
		t.Fatalf("expected positive AllocBytes, got: %d", stats.AllocBytes)
	}
	if stats.SysBytes <= 0 {
		t.Fatalf("expected positive SysBytes, got: %d", stats.SysBytes)
	}
	if stats.NumGoroutines <= 0 {
		t.Fatalf("expected positive NumGoroutines, got: %d", stats.NumGoroutines)
	}

	t.Logf("Memory stats: Alloc=%s, Sys=%s, Goroutines=%d, NumGC=%d",
		stats.AllocMb, stats.SysMb, stats.NumGoroutines, stats.NumGC)
}

// The UI polls memory stats periodically while the tunnel forwards traffic:
// the metrics-based read must stay allocation-free, unlike MemStats.
func BenchmarkReadMemoryStats(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ReadMemoryStats()
	}
}

// Reference point: the legacy stop-the-world read this benchmark contrasts
// against BenchmarkReadMemoryStats.
func BenchmarkLegacyReadMemStats(b *testing.B) {
	var m runtime.MemStats
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		runtime.ReadMemStats(&m)
	}
}

func TestFastSelectBestOutbound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	configJSON := `{
		"log": { "loglevel": "none" },
		"outbounds": [
			{ "protocol": "freedom", "tag": "direct" },
			{ "protocol": "blackhole", "tag": "dead-node" }
		]
	}`

	best := FastSelectBestOutbound(configJSON, "dead-node,direct", ts.URL, 1500)
	if best != "direct" {
		t.Fatalf("expected 'direct' to be selected over dead-node, got: %s", best)
	}
	t.Logf("FastSelectBestOutbound correctly selected: %s", best)
}

func TestStartLoopPublishesAndStopLoopClearsTunFdEnv(t *testing.T) {
	unsetEnvVariable(tunFdKey)
	unsetEnvVariable(v2rayTunFdKey)

	configJSON := `{
		"log": { "loglevel": "none" },
		"outbounds": [
			{ "protocol": "freedom", "tag": "direct" }
		]
	}`

	ctrl := NewCoreController(&dummyCallbackHandler{})
	if err := ctrl.StartLoop(configJSON, 12345); err != nil {
		t.Fatalf("StartLoop failed: %v", err)
	}

	if got := os.Getenv(tunFdKey); got != "12345" {
		t.Fatalf("expected %s=12345 while running, got %q", tunFdKey, got)
	}
	if got := os.Getenv(v2rayTunFdKey); got != "12345" {
		t.Fatalf("expected %s=12345 while running, got %q", v2rayTunFdKey, got)
	}

	if err := ctrl.StopLoop(); err != nil {
		t.Fatalf("StopLoop failed: %v", err)
	}

	if got := os.Getenv(tunFdKey); got != "" {
		t.Fatalf("expected %s cleared after StopLoop, got %q", tunFdKey, got)
	}
	if got := os.Getenv(v2rayTunFdKey); got != "" {
		t.Fatalf("expected %s cleared after StopLoop, got %q", v2rayTunFdKey, got)
	}
}

func TestStartLoopFailureDoesNotTouchTunFdEnv(t *testing.T) {
	unsetEnvVariable(tunFdKey)
	unsetEnvVariable(v2rayTunFdKey)

	ctrl := NewCoreController(&dummyCallbackHandler{})
	if err := ctrl.StartLoop("{not valid json", 5555); err == nil {
		t.Fatal("expected StartLoop to fail on invalid config")
	}

	if got := os.Getenv(tunFdKey); got != "" {
		t.Fatalf("failed start must not publish %s, got %q", tunFdKey, got)
	}
	if got := os.Getenv(v2rayTunFdKey); got != "" {
		t.Fatalf("failed start must not publish %s, got %q", v2rayTunFdKey, got)
	}
}

type dummySocketProtector struct {
	protectedCount int
}

func (p *dummySocketProtector) Protect(fd int) bool {
	p.protectedCount++
	return true
}

func TestOlcRtcParsing(t *testing.T) {
	yamlConfig := `
mode: cnc
provider: jitsi
transport: datachannel
room: test-room-123
key: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
dns: 1.1.1.1:53
socks5_listen: 127.0.0.1:10808
`
	cfg, err := ParseOlcRtcOptions(yamlConfig, 10808)
	if err != nil {
		t.Fatalf("ParseOlcRtcOptions failed: %v", err)
	}
	if cfg.Provider != "jitsi" {
		t.Errorf("expected provider jitsi, got %s", cfg.Provider)
	}
	if cfg.Transport != "datachannel" {
		t.Errorf("expected transport datachannel, got %s", cfg.Transport)
	}
	if cfg.Room != "test-room-123" {
		t.Errorf("expected room test-room-123, got %s", cfg.Room)
	}
	if cfg.Key != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Errorf("unexpected key: %s", cfg.Key)
	}
	if cfg.Socks.Port != 10808 {
		t.Errorf("expected socks port 10808, got %d", cfg.Socks.Port)
	}
}

func TestOlcRtcTransportOptionsParsing(t *testing.T) {
	// Test VP8 with angle brackets in transport
	vp8Yaml := `
mode: cnc
provider: telemost
transport: vp8channel<vp8-fps=25&vp8-batch=1>
room: 56026201482837
key: 30330bd1da1c7ad6e7d518e423662b3bb2b53ca1bbb65612263a494610fa73e4
dns: 1.1.1.1:53
socks5_listen: 127.0.0.1:10808
`
	cfg, err := ParseOlcRtcOptions(vp8Yaml, 10808)
	if err != nil {
		t.Fatalf("ParseOlcRtcOptions failed for vp8: %v", err)
	}
	if cfg.Transport != "vp8channel" {
		t.Errorf("expected transport vp8channel, got %s", cfg.Transport)
	}
	if cfg.VP8.FPS != 25 {
		t.Errorf("expected vp8.fps 25, got %d", cfg.VP8.FPS)
	}
	if cfg.VP8.BatchSize != 1 {
		t.Errorf("expected vp8.batch_size 1, got %d", cfg.VP8.BatchSize)
	}

	// Test SEI with angle brackets in transport
	seiYaml := `
mode: cnc
provider: wbstream
transport: seichannel<fps=60&batch=64&frag=900&ack-ms=2000>
room: room-01
key: 30330bd1da1c7ad6e7d518e423662b3bb2b53ca1bbb65612263a494610fa73e4
dns: 1.1.1.1:53
socks5_listen: 127.0.0.1:10808
`
	cfgSei, err := ParseOlcRtcOptions(seiYaml, 10808)
	if err != nil {
		t.Fatalf("ParseOlcRtcOptions failed for sei: %v", err)
	}
	if cfgSei.Transport != "seichannel" {
		t.Errorf("expected transport seichannel, got %s", cfgSei.Transport)
	}
	if cfgSei.SEI.FPS != 60 || cfgSei.SEI.BatchSize != 64 || cfgSei.SEI.FragmentSize != 900 || cfgSei.SEI.AckTimeoutMS != 2000 {
		t.Errorf("unexpected sei options: %+v", cfgSei.SEI)
	}

	// Test Video with angle brackets in transport
	videoYaml := `
mode: cnc
provider: telemost
transport: videochannel<video-w=1080&video-h=1080&video-fps=60&video-codec=qrcode>
room: room-01
key: 30330bd1da1c7ad6e7d518e423662b3bb2b53ca1bbb65612263a494610fa73e4
dns: 1.1.1.1:53
socks5_listen: 127.0.0.1:10808
`
	cfgVideo, err := ParseOlcRtcOptions(videoYaml, 10808)
	if err != nil {
		t.Fatalf("ParseOlcRtcOptions failed for video: %v", err)
	}
	if cfgVideo.Transport != "videochannel" {
		t.Errorf("expected transport videochannel, got %s", cfgVideo.Transport)
	}
	if cfgVideo.Video.Width != 1080 || cfgVideo.Video.Height != 1080 || cfgVideo.Video.FPS != 60 || cfgVideo.Video.Codec != "qrcode" {
		t.Errorf("unexpected video options: %+v", cfgVideo.Video)
	}

	// Test VP8 with separate YAML block
	vp8BlockYaml := `
mode: cnc
provider: telemost
transport: vp8channel
vp8:
  fps: 25
  batch_size: 1
room: 56026201482837
key: 30330bd1da1c7ad6e7d518e423662b3bb2b53ca1bbb65612263a494610fa73e4
dns: 1.1.1.1:53
socks5_listen: 127.0.0.1:10808
`
	cfgBlock, err := ParseOlcRtcOptions(vp8BlockYaml, 10808)
	if err != nil {
		t.Fatalf("ParseOlcRtcOptions failed for vp8 block: %v", err)
	}
	if cfgBlock.VP8.FPS != 25 || cfgBlock.VP8.BatchSize != 1 {
		t.Errorf("unexpected vp8 block options: %+v", cfgBlock.VP8)
	}
}

func TestOlcRtcProtectorAndState(t *testing.T) {
	protector := &dummySocketProtector{}
	SetOlcRtcSocketProtector(protector)

	if IsOlcRtcRunning() {
		t.Fatal("expected olcrtc to not be running initially")
	}
	if state := OlcRtcState(); state != "stopped" && state != "idle" {
		t.Fatalf("expected state stopped/idle, got %s", state)
	}
	if err := StopOlcRtc(); err != nil {
		t.Fatalf("StopOlcRtc failed: %v", err)
	}
}

func TestOlcRtcSocksCredentialsAndNestedRoom(t *testing.T) {
	// Test canonical nested format as generated by owenclave-dev
	nestedYaml := `
mode: cnc
auth:
  provider: telemost
room:
  id: "56026201482837"
crypto:
  key: "30330bd1da1c7ad6e7d518e423662b3bb2b53ca1bbb65612263a494610fa73e4"
net:
  transport: vp8channel
  dns: 1.1.1.1:53
socks:
  host: "127.0.0.1"
  port: 10808
  user: "test_user"
  pass: "test_pass"
`
	cfg, err := ParseOlcRtcOptions(nestedYaml, 10808)
	if err != nil {
		t.Fatalf("ParseOlcRtcOptions failed for nested yaml: %v", err)
	}
	if cfg.Provider != "telemost" {
		t.Errorf("expected provider telemost, got %s", cfg.Provider)
	}
	if cfg.Room != "56026201482837" {
		t.Errorf("expected room 56026201482837, got %s", cfg.Room)
	}
	if cfg.Key != "30330bd1da1c7ad6e7d518e423662b3bb2b53ca1bbb65612263a494610fa73e4" {
		t.Errorf("expected key to match, got %s", cfg.Key)
	}
	if cfg.Socks5User != "test_user" {
		t.Errorf("expected socks5_user test_user, got %s", cfg.Socks5User)
	}
	if cfg.Socks5Pass != "test_pass" {
		t.Errorf("expected socks5_pass test_pass, got %s", cfg.Socks5Pass)
	}

	// Test flat format as generated by skipi-box
	flatYaml := `
mode: cnc
provider: telemost
transport: vp8channel
room: 56026201482837
key: 30330bd1da1c7ad6e7d518e423662b3bb2b53ca1bbb65612263a494610fa73e4
dns: 1.1.1.1:53
socks5_listen: 127.0.0.1:10808
socks5_user: flat_user
socks5_pass: flat_pass
`
	cfgFlat, err := ParseOlcRtcOptions(flatYaml, 10808)
	if err != nil {
		t.Fatalf("ParseOlcRtcOptions failed for flat yaml: %v", err)
	}
	if cfgFlat.Room != "56026201482837" {
		t.Errorf("expected room 56026201482837, got %s", cfgFlat.Room)
	}
	if cfgFlat.Socks5User != "flat_user" {
		t.Errorf("expected socks5_user flat_user, got %s", cfgFlat.Socks5User)
	}
	if cfgFlat.Socks5Pass != "flat_pass" {
		t.Errorf("expected socks5_pass flat_pass, got %s", cfgFlat.Socks5Pass)
	}
}

func TestWaitOlcRtcReadyNotRunning(t *testing.T) {
	err := WaitOlcRtcReady(500)
	if err == nil {
		t.Fatal("expected error when WaitOlcRtcReady called while runtime not active")
	}
}

func TestAmneziaWgConfigAndIpc(t *testing.T) {
	awgJSON := `{
		"protocol": "wireguard",
		"settings": {
			"secretKey": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=",
			"address": ["10.8.0.2/32"],
			"dnsServers": ["9.9.9.9"],
			"peers": [
				{
					"publicKey": "YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=",
					"endpoint": "192.0.2.1:51820",
					"allowedIPs": ["0.0.0.0/0"],
					"keepAlive": 25
				}
			],
			"mtu": 1420,
			"jc": 5,
			"jmin": 30,
			"jmax": 80,
			"s1": 20,
			"s2": 40,
			"s3": 60,
			"s4": 80,
			"h1": 11111,
			"h2": 22222,
			"h3": 33333,
			"h4": 44444
		}
	}`

	settings, err := ParseAmneziaWgSettings(awgJSON)
	if err != nil {
		t.Fatalf("ParseAmneziaWgSettings failed: %v", err)
	}
	if !settings.HasAmneziaParams() {
		t.Fatal("expected HasAmneziaParams to be true")
	}
	if settings.Jc != 5 || settings.Jmin != 30 || settings.Jmax != 80 {
		t.Fatalf("unexpected Jc/Jmin/Jmax: %d/%d/%d", settings.Jc, settings.Jmin, settings.Jmax)
	}
	if settings.S1 != 20 || settings.S2 != 40 || settings.S3 != 60 || settings.S4 != 80 {
		t.Fatalf("unexpected S1/S2/S3/S4: %d/%d/%d/%d", settings.S1, settings.S2, settings.S3, settings.S4)
	}
	if len(settings.DNSServers) != 1 || settings.DNSServers[0] != "9.9.9.9" {
		t.Fatalf("unexpected DNS servers: %#v", settings.DNSServers)
	}

	ipc, err := settings.BuildIpcConfig()
	if err != nil {
		t.Fatalf("BuildIpcConfig failed: %v", err)
	}
	if !strings.Contains(ipc, "jc=5") {
		t.Errorf("ipc missing jc=5: %s", ipc)
	}
	if !strings.Contains(ipc, "jmin=30") {
		t.Errorf("ipc missing jmin=30: %s", ipc)
	}
	if !strings.Contains(ipc, "jmax=80") {
		t.Errorf("ipc missing jmax=80: %s", ipc)
	}
	if !strings.Contains(ipc, "s1=20") {
		t.Errorf("ipc missing s1=20: %s", ipc)
	}
	if !strings.Contains(ipc, "s2=40") {
		t.Errorf("ipc missing s2=40: %s", ipc)
	}
	if !strings.Contains(ipc, "s3=60") || !strings.Contains(ipc, "s4=80") {
		t.Errorf("ipc missing s3/s4: %s", ipc)
	}
	if !strings.Contains(ipc, "h1=11111") {
		t.Errorf("ipc missing h1=11111: %s", ipc)
	}

	fullConfig := fmt.Sprintf(`{
		"outbounds": [
			%s
		]
	}`, awgJSON)
	rewritten := RewriteWireguardOutboundToSocks(fullConfig, 10809)
	if !strings.Contains(rewritten, `"protocol":"socks"`) {
		t.Fatalf("expected rewritten config to contain protocol socks, got: %s", rewritten)
	}
	if !strings.Contains(rewritten, `10809`) {
		t.Fatalf("expected rewritten config to contain port 10809, got: %s", rewritten)
	}
}

func TestAmneziaWgRunnerLifecycle(t *testing.T) {
	protector := &dummySocketProtector{}
	SetAmneziaWgSocketProtector(protector)
	defer SetAmneziaWgSocketProtector(nil)

	awgJSON := `{
		"secretKey": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=",
		"address": ["10.8.0.2/32"],
		"dnsServers": ["1.1.1.1"],
		"peers": [
			{
				"publicKey": "YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=",
				"endpoint": "127.0.0.1:59999",
				"allowedIPs": ["0.0.0.0/0"]
			}
		],
		"jc": 3,
		"jmin": 40,
		"jmax": 70,
		"s1": 15,
		"s2": 25,
		"h1": "12345"
	}`

	settings, err := ParseAmneziaWgSettings(awgJSON)
	if err != nil {
		t.Fatalf("ParseAmneziaWgSettings failed: %v", err)
	}

	runner, err := NewAmneziaWgRunner(settings, 0)
	if err != nil {
		t.Fatalf("NewAmneziaWgRunner failed: %v", err)
	}

	if err := runner.Start(); err != nil {
		t.Fatalf("runner.Start failed: %v", err)
	}
	if runner.socksPort <= 0 {
		t.Fatalf("expected positive socks port, got %d", runner.socksPort)
	}
	if protector.protectedCount == 0 {
		t.Fatal("expected AmneziaWG peer sockets to be passed through the protector")
	}

	// SOCKS5 handshake test to verify listener is functioning
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", runner.socksPort))
	if err != nil {
		t.Fatalf("failed to dial socks listener: %v", err)
	}
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	var reply [2]byte
	_, _ = io.ReadFull(conn, reply[:])
	conn.Close()
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("unexpected socks handshake reply: %v", reply)
	}

	if err := runner.Stop(); err != nil {
		t.Fatalf("runner.Stop failed: %v", err)
	}
}

func TestAmneziaWgRequiresExplicitDNS(t *testing.T) {
	_, err := (&AmneziaWgSettings{}).netstackDNSAddresses()
	if err == nil || !strings.Contains(err.Error(), "dnsServers is required") {
		t.Fatalf("expected missing DNS error, got %v", err)
	}

	_, err = (&AmneziaWgSettings{DNSServers: []string{"https://dns.example/dns-query"}}).netstackDNSAddresses()
	if err == nil || !strings.Contains(err.Error(), "invalid AmneziaWG DNS server") {
		t.Fatalf("expected raw-IP DNS validation error, got %v", err)
	}
}

func TestOlcRtcRequiresRawDNS(t *testing.T) {
	if _, err := ParseOlcRtcOptions("dns: ''", 10808); err == nil || !strings.Contains(err.Error(), "dns is required") {
		t.Fatalf("expected required DNS error, got %v", err)
	}
	if _, err := ParseOlcRtcOptions("dns: 'https://dns.example/dns-query'", 10808); err == nil || !strings.Contains(err.Error(), "raw host:port") {
		t.Fatalf("expected DoH DNS validation error, got %v", err)
	}
}
