package skipicore

import (
	"context"
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
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
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

func TestMeasureOutboundDownloadReadsExactRequestedBytes(t *testing.T) {
	const requestedBytes = int64(256 * 1024)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Cache-Control"); got != "no-cache" {
			t.Errorf("expected no-cache request header, got %q", got)
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", requestedBytes))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, strings.Repeat("x", int(requestedBytes)))
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

	encoded, err := MeasureOutboundDownload(
		configJSON,
		ts.URL,
		requestedBytes,
		10_000,
		"",
	)
	if err != nil {
		t.Fatalf("MeasureOutboundDownload failed: %v", err)
	}

	var result outboundDownloadResult
	if err := json.Unmarshal([]byte(encoded), &result); err != nil {
		t.Fatalf("invalid download result JSON: %v; value=%s", err, encoded)
	}
	if result.BytesDownloaded != requestedBytes {
		t.Fatalf("expected %d downloaded bytes, got %d", requestedBytes, result.BytesDownloaded)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, result.StatusCode)
	}
	if result.ElapsedMillis < 0 || result.TtfbMillis < 0 {
		t.Fatalf("expected non-negative timings, got elapsed=%d ttfb=%d", result.ElapsedMillis, result.TtfbMillis)
	}
}

func TestMeasureOutboundDownloadRejectsUnsafeLimits(t *testing.T) {
	if _, err := MeasureOutboundDownload("{}", "https://example.com", 0, 10_000, ""); err == nil {
		t.Fatal("expected zero-byte download to be rejected")
	}
	if _, err := MeasureOutboundDownload("{}", "https://example.com", maxOutboundDownloadBytes+1, 10_000, ""); err == nil {
		t.Fatal("expected oversized download to be rejected")
	}
	if _, err := MeasureOutboundDownload("{}", "https://example.com", 1, minOutboundDownloadTimeoutMillis-1, ""); err == nil {
		t.Fatal("expected short timeout to be rejected")
	}
}

func TestCancelOutboundDownloadStopsRunningRequest(t *testing.T) {
	started := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1")
		w.WriteHeader(http.StatusOK)
		close(started)
		<-r.Context().Done()
	}))
	defer ts.Close()

	configJSON := `{
		"log": { "loglevel": "none" },
		"outbounds": [{ "protocol": "freedom", "tag": "direct" }]
	}`
	const requestID = "cancel-outbound-download-test"
	done := make(chan error, 1)
	go func() {
		_, err := MeasureOutboundDownload(configJSON, ts.URL, 1, 60_000, requestID)
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("download request did not start")
	}

	CancelOutboundDownload(requestID)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected cancelled download to return an error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled download did not stop promptly")
	}
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

// A start that fails after some inbounds are already listening must give those listeners back,
// otherwise every retry reports "address already in use" until the process exits.
func TestStartLoopFailureReleasesListenersAndTunFdEnv(t *testing.T) {
	unsetEnvVariable(tunFdKey)
	unsetEnvVariable(v2rayTunFdKey)

	freePort := reserveLocalPort(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port

	configJSON := fmt.Sprintf(`{
		"log": { "loglevel": "none" },
		"inbounds": [
			{ "listen": "127.0.0.1", "port": %d, "protocol": "socks", "settings": { "auth": "noauth" } },
			{ "listen": "127.0.0.1", "port": %d, "protocol": "socks", "settings": { "auth": "noauth" } }
		],
		"outbounds": [ { "protocol": "freedom", "tag": "direct" } ]
	}`, freePort, busyPort)

	ctrl := NewCoreController(&dummyCallbackHandler{})
	if err := ctrl.StartLoop(configJSON, 7777); err == nil {
		t.Fatal("expected StartLoop to fail because one inbound port is taken")
	}

	if ctrl.IsRunning() {
		t.Fatal("a failed start must not leave the controller running")
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", freePort))
	if err != nil {
		t.Fatalf("the inbound that did start was not released: %v", err)
	}
	_ = listener.Close()
	if got := os.Getenv(tunFdKey); got != "" {
		t.Fatalf("failed start must not leave %s set, got %q", tunFdKey, got)
	}
	if got := os.Getenv(v2rayTunFdKey); got != "" {
		t.Fatalf("failed start must not leave %s set, got %q", v2rayTunFdKey, got)
	}
}

func reserveLocalPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve local port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release local port: %v", err)
	}
	return port
}

type dummySocketProtector struct {
	protectedCount int
}

func (p *dummySocketProtector) Protect(fd int) bool {
	p.protectedCount++
	return true
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

func TestAmneziaWgSupportsHeaderRangesAndObfuscationChains(t *testing.T) {
	settings := &AmneziaWgSettings{
		SecretKey:  "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=",
		DNSServers: []string{"9.9.9.9"},
		Jc:         9,
		Jmin:       30,
		Jmax:       90,
		S1:         110,
		S2:         120,
		S3:         47,
		S4:         23,
		H1:         "7291435-486117520",
		H2:         "602843917-1157629843",
		H3:         "1249871566-1680354947",
		H4:         "1781926002-2106438100",
		I1:         "<b 0x0003><r 2><b 0x2112A442><r 12><r 20>",
		I2:         "<b 0x0103><r 2><b 0x2112A442><r 12><r 24>",
		I3:         "<b 0x0008><r 2><b 0x2112A442><r 12><r 16>",
		Peers: []*AmneziaWgPeer{{
			PublicKey:  "YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=",
			Endpoint:   "198.51.100.2:50125",
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		}},
	}

	if err := settings.validateNativeRunnerCompatibility(); err != nil {
		t.Fatalf("valid AmneziaWG ranges/chains were rejected: %v", err)
	}
	if !settings.HasAmneziaParams() {
		t.Fatal("expected I/H settings to count as AmneziaWG parameters")
	}
	ipc, err := settings.BuildIpcConfig()
	if err != nil {
		t.Fatalf("BuildIpcConfig failed: %v", err)
	}
	for _, expected := range []string{
		"h1=7291435-486117520",
		"h4=1781926002-2106438100",
		"i1=<b 0x0003><r 2><b 0x2112A442><r 12><r 20>",
		"i3=<b 0x0008><r 2><b 0x2112A442><r 12><r 16>",
	} {
		if !strings.Contains(ipc, expected) {
			t.Errorf("IPC config is missing %q: %s", expected, ipc)
		}
	}
}

func TestAmneziaWgRejectsUnsafeJunkCountBeforeRunnerStartup(t *testing.T) {
	settings := &AmneziaWgSettings{
		Jc: 129,
		Peers: []*AmneziaWgPeer{{
			Endpoint: "198.51.100.2:51820",
		}},
	}

	err := settings.validateNativeRunnerCompatibility()
	if err == nil || !strings.Contains(err.Error(), "jc") {
		t.Fatalf("expected unsafe jc to be rejected, got %v", err)
	}
}

func TestResolveAmneziaWgEndpointPrefersIPv4Literal(t *testing.T) {
	endpoint, err := resolveAmneziaWgEndpoint("relay.example:50125", func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "relay.example" {
			t.Fatalf("unexpected lookup host %q", host)
		}
		return []netip.Addr{
			netip.MustParseAddr("2001:db8::10"),
			netip.MustParseAddr("198.51.100.25"),
		}, nil
	})
	if err != nil {
		t.Fatalf("resolveAmneziaWgEndpoint failed: %v", err)
	}
	if endpoint != "198.51.100.25:50125" {
		t.Fatalf("unexpected resolved endpoint %q", endpoint)
	}
}

func TestAmneziaWgEndpointLookupFallsBackToConfiguredDNS(t *testing.T) {
	systemLookups := 0
	configuredDNSLookups := 0
	addresses, err := lookupAmneziaWgHostWithFallback(
		context.Background(),
		"relay.example",
		func(_ context.Context, host string) ([]netip.Addr, error) {
			systemLookups++
			if host != "relay.example" {
				t.Fatalf("unexpected system lookup host %q", host)
			}
			return nil, fmt.Errorf("system resolver unavailable")
		},
		func(_ context.Context, host string) ([]netip.Addr, error) {
			configuredDNSLookups++
			if host != "relay.example" {
				t.Fatalf("unexpected configured DNS lookup host %q", host)
			}
			return []netip.Addr{netip.MustParseAddr("198.51.100.25")}, nil
		},
	)
	if err != nil {
		t.Fatalf("configured DNS fallback failed: %v", err)
	}
	if systemLookups != 1 || configuredDNSLookups != 1 {
		t.Fatalf("expected one system and one configured DNS lookup, got system=%d configured=%d", systemLookups, configuredDNSLookups)
	}
	if len(addresses) != 1 || addresses[0].String() != "198.51.100.25" {
		t.Fatalf("unexpected fallback addresses %v", addresses)
	}
}

func TestAmneziaWgUDPBindAddressSelectsConfiguredLocalFamily(t *testing.T) {
	localAddrs := []netip.Addr{
		netip.MustParseAddr("10.125.77.96"),
		netip.MustParseAddr("fd00::96"),
	}
	tests := []struct {
		name        string
		destination *net.UDPAddr
		wantFamily  string
		wantIP      net.IP
	}{
		{
			name:        "ipv4",
			destination: &net.UDPAddr{IP: net.ParseIP("198.51.100.25"), Port: 53},
			wantFamily:  "ipv4",
			wantIP:      net.ParseIP("10.125.77.96"),
		},
		{
			name:        "ipv6",
			destination: &net.UDPAddr{IP: net.ParseIP("2001:db8::53"), Port: 53},
			wantFamily:  "ipv6",
			wantIP:      net.ParseIP("fd00::96"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bind, family, err := amneziaWgUDPBindAddress(test.destination, localAddrs)
			if err != nil {
				t.Fatalf("amneziaWgUDPBindAddress failed: %v", err)
			}
			if family != test.wantFamily {
				t.Fatalf("expected family %q, got %q", test.wantFamily, family)
			}
			if bind.Port != 0 || !bind.IP.Equal(test.wantIP) {
				t.Fatalf("unexpected bind address %v", bind)
			}
		})
	}

	if _, _, err := amneziaWgUDPBindAddress(nil, localAddrs); err == nil {
		t.Fatal("expected missing destination to be rejected before netstack access")
	}
	if _, _, err := amneziaWgUDPBindAddress(
		&net.UDPAddr{IP: net.ParseIP("2001:db8::53"), Port: 53},
		[]netip.Addr{netip.MustParseAddr("10.125.77.96")},
	); err == nil {
		t.Fatal("expected an IPv6 destination without an IPv6 tunnel address to be rejected")
	}
}

func TestAmneziaWgUDPBindAddressCreatesUsableNetstackEndpoints(t *testing.T) {
	localAddrs := []netip.Addr{
		netip.MustParseAddr("10.125.77.96"),
		netip.MustParseAddr("fd00::96"),
	}
	device, tnet, err := netstack.CreateNetTUN(localAddrs, nil, 1280)
	if err != nil {
		t.Fatalf("CreateNetTUN failed: %v", err)
	}
	defer func() { _ = device.Close() }()

	for _, destination := range []*net.UDPAddr{
		{IP: net.ParseIP("198.51.100.25"), Port: 53},
		{IP: net.ParseIP("2001:db8::53"), Port: 53},
	} {
		bind, _, err := amneziaWgUDPBindAddress(destination, localAddrs)
		if err != nil {
			t.Fatalf("amneziaWgUDPBindAddress failed: %v", err)
		}
		conn, err := tnet.ListenUDP(bind)
		if err != nil {
			t.Fatalf("ListenUDP(%v) failed: %v", bind, err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("Close UDP endpoint failed: %v", err)
		}
	}
}

