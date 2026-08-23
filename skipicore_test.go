package skipicore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
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


