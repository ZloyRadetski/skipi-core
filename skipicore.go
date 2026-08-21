// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	quic "github.com/apernet/quic-go"
	coreapplog "github.com/xtls/xray-core/app/log"
	corecommlog "github.com/xtls/xray-core/common/log"
	corenet "github.com/xtls/xray-core/common/net"
	corefilesystem "github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	corestats "github.com/xtls/xray-core/features/stats"
	coreserial "github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	browser_dialer "github.com/xtls/xray-core/transport/internet/browser_dialer"
	mobasset "golang.org/x/mobile/asset"
)

// Constants for environment variables and core identification
const (
	coreAsset            = "xray.location.asset"
	coreCert             = "xray.location.cert"
	v2rayAsset           = "v2ray.location.asset"
	xudpBaseKey          = "xray.xudp.basekey"
	tunFdKey             = "xray.tun.fd"
	v2rayTunFdKey        = "v2ray.tun.fd"
	browserDialerAddress = "xray.browser.dialer"
	coreLibVersion       = 1
)

// CoreCallbackHandler handles lifecycle and logging events from the core.
type CoreCallbackHandler interface {
	Startup() int64
	Shutdown() int64
	OnEmitStatus(code int64, message string) int64
}

// ProcessFinder is an interface for Android process-based routing (Split Tunneling).
type ProcessFinder interface {
	FindProcessByConnection(network, srcIP string, srcPort int, destIP string, destPort int) int
}

// consoleLogWriter implements a lightweight log writer without redundant timestamps,
// as the Android Logcat system already timestamps all log entries.
type consoleLogWriter struct {
	logger *log.Logger
}

func (w *consoleLogWriter) Write(s string) error {
	w.logger.Print(s)
	return nil
}

func (w *consoleLogWriter) Close() error {
	return nil
}

func createStdoutLogWriter() corecommlog.WriterCreator {
	return func() corecommlog.Writer {
		return &consoleLogWriter{
			logger: log.New(os.Stdout, "", 0),
		}
	}
}

// setEnvVariable safely sets an environment variable.
func setEnvVariable(key, value string) {
	if err := os.Setenv(key, value); err != nil {
		log.Printf("Failed to set environment variable %s: %v", key, err)
	}
}

// unsetEnvVariable safely unsets an environment variable.
func unsetEnvVariable(key string) {
	_ = os.Unsetenv(key)
}

// CoreController manages the lifecycle, stats, and real-time monitoring of an Xray-core instance.
type CoreController struct {
	mu           sync.Mutex
	instance     *core.Instance
	statsManager corestats.Manager
	callback     CoreCallbackHandler
	isRunning    bool
}

// NewCoreController creates a new CoreController with the provided callback handler.
func NewCoreController(handler CoreCallbackHandler) *CoreController {
	_ = coreapplog.RegisterHandlerCreator(
		coreapplog.LogType_Console,
		func(lt coreapplog.LogType, options coreapplog.HandlerCreatorOptions) (corecommlog.Handler, error) {
			return corecommlog.NewLogger(createStdoutLogWriter()), nil
		},
	)

	return &CoreController{
		callback: handler,
	}
}

// StartLoop initializes and starts the Xray core instance with given JSON config and optional TUN file descriptor.
func (c *CoreController) StartLoop(configJSON string, tunFd int64) error {
	if tunFd > 0 {
		fdStr := strconv.FormatInt(tunFd, 10)
		setEnvVariable(tunFdKey, fdStr)
		setEnvVariable(v2rayTunFdKey, fdStr)
	} else {
		unsetEnvVariable(tunFdKey)
		unsetEnvVariable(v2rayTunFdKey)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isRunning {
		return errors.New("core instance is already running")
	}

	config, err := coreserial.LoadJSONConfig(strings.NewReader(configJSON))
	if err != nil {
		return fmt.Errorf("failed to load xray config: %w", err)
	}

	server, err := core.New(config)
	if err != nil {
		return fmt.Errorf("failed to create xray instance: %w", err)
	}

	if mgr := server.GetFeature(corestats.ManagerType()); mgr != nil {
		if sm, ok := mgr.(corestats.Manager); ok {
			c.statsManager = sm
		}
	}

	if err := server.Start(); err != nil {
		c.statsManager = nil
		return fmt.Errorf("failed to start xray instance: %w", err)
	}

	c.instance = server
	c.isRunning = true

	if c.callback != nil {
		c.callback.Startup()
		c.callback.OnEmitStatus(0, "Started successfully, running")
	}

	return nil
}

// StopLoop gracefully shuts down the running Xray instance.
func (c *CoreController) StopLoop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isRunning || c.instance == nil {
		return nil
	}

	err := c.instance.Close()
	c.instance = nil
	c.statsManager = nil
	c.isRunning = false

	if c.callback != nil {
		c.callback.Shutdown()
		c.callback.OnEmitStatus(0, "Core stopped")
	}

	return err
}

// IsRunning returns whether the core instance is currently running.
func (c *CoreController) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isRunning
}

// MeasureDelay measures network latency to a target URL through the currently running core instance.
func (c *CoreController) MeasureDelay(targetURL string) (int64, error) {
	c.mu.Lock()
	inst := c.instance
	c.mu.Unlock()

	if inst == nil {
		return -1, errors.New("core instance is not running")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	return measureInstanceDelay(ctx, inst, targetURL)
}

// QueryAllOutboundTrafficStats retrieves and resets all outbound traffic counters in memory.
// Returns a compact string: "tag,direction,value;tag,direction,value;".
func (c *CoreController) QueryAllOutboundTrafficStats() string {
	c.mu.Lock()
	sm := c.statsManager
	c.mu.Unlock()

	if sm == nil {
		return ""
	}

	var b strings.Builder
	sm.VisitCounters(func(name string, counter corestats.Counter) bool {
		parts := strings.Split(name, ">>>")
		if len(parts) != 4 || parts[0] != "outbound" || parts[2] != "traffic" {
			return true
		}

		tag := parts[1]
		direct := parts[3]
		value := counter.Set(0)
		if value <= 0 {
			return true
		}

		b.WriteString(tag)
		b.WriteByte(',')
		b.WriteString(direct)
		b.WriteByte(',')
		b.WriteString(strconv.FormatInt(value, 10))
		b.WriteByte(';')
		return true
	})
	return b.String()
}

// InitCoreEnv configures environment variables (assets and certificate path) and sets up
// the fallback file reader to directly read assets from Android APK if missing on disk.
func InitCoreEnv(dataDir string, assetKey string) {
	if len(dataDir) > 0 {
		setEnvVariable(coreAsset, dataDir)
		setEnvVariable(coreCert, dataDir)
		setEnvVariable(v2rayAsset, dataDir)
	}
	if len(assetKey) > 0 {
		setEnvVariable(xudpBaseKey, assetKey)
	}

	corefilesystem.NewFileReader = func(path string) (io.ReadCloser, error) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			_, file := filepath.Split(path)
			return mobasset.Open(file)
		}
		return os.Open(path)
	}
}

// CoreVersion returns the version of the underlying Xray-core engine.
func CoreVersion() string {
	return core.Version()
}

// CheckVersionX returns the SKIPI core wrapper version along with the underlying Xray-core engine version.
func CheckVersionX() string {
	return fmt.Sprintf("SkipiCore v%d, Xray-core v%s", coreLibVersion, core.Version())
}

// ReconcileBrowserDialer updates the browser dialer address and reloads its configuration.
func ReconcileBrowserDialer(dialerAddr string) {
	setEnvVariable(browserDialerAddress, dialerAddr)
	browser_dialer.Reload()
}

// MeasureOutboundDelay tests the latency of an outbound proxy configuration against a target URL.
// It optimizes performance by stripping inbounds and non-essential app modules.
func MeasureOutboundDelay(configJSON string, targetURL string) (int64, error) {
	config, err := coreserial.LoadJSONConfig(strings.NewReader(configJSON))
	if err != nil {
		return -1, fmt.Errorf("failed to parse test config: %w", err)
	}

	// Optimize test instance by removing inbounds and non-essential apps
	config.Inbound = nil
	var essentialApps []*serial.TypedMessage
	for _, app := range config.App {
		if app.Type == "xray.app.proxyman.OutboundConfig" ||
			app.Type == "xray.app.dispatcher.Config" ||
			app.Type == "xray.app.log.Config" {
			essentialApps = append(essentialApps, app)
		}
	}
	config.App = essentialApps

	server, err := core.New(config)
	if err != nil {
		return -1, fmt.Errorf("failed to create test instance: %w", err)
	}

	if err := server.Start(); err != nil {
		return -1, fmt.Errorf("failed to start test instance: %w", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	return measureInstanceDelay(ctx, server, targetURL)
}

// measureInstanceDelay measures network latency for an instance to a given target URL with 2 attempts and jitter reduction.
func measureInstanceDelay(ctx context.Context, inst *core.Instance, targetURL string) (int64, error) {
	if inst == nil {
		return -1, errors.New("core instance is nil")
	}

	if targetURL == "" {
		targetURL = "https://www.google.com/generate_204"
	}

	tr := &http.Transport{
		TLSHandshakeTimeout: 6 * time.Second,
		DisableKeepAlives:   false,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := corenet.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
			if err != nil {
				return nil, err
			}
			return core.Dial(ctx, inst, dest)
		},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   12 * time.Second,
	}

	var minDuration int64 = -1
	success := false
	var lastErr error

	const attempts = 2
	for i := 0; i < attempts; i++ {
		select {
		case <-ctx.Done():
			if !success {
				return -1, ctx.Err()
			}
			return minDuration, nil
		default:
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to create HTTP request: %w", err)
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			lastErr = fmt.Errorf("invalid status code: %s", resp.Status)
			continue
		}

		if err != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", err)
			continue
		}

		duration := time.Since(start).Milliseconds()
		if !success || duration < minDuration {
			minDuration = duration
		}
		success = true
	}

	if !success {
		return -1, lastErr
	}
	return minDuration, nil
}

type certSha256Request struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	ServerName string `json:"serverName"`
	TimeoutMs  int64  `json:"timeoutMs"`
}

type certSha256Result struct {
	Sha256 string `json:"sha256,omitempty"`
	Error  string `json:"error,omitempty"`
}

// FetchTlsCertSha256 extracts the SHA-256 fingerprint of a remote server's TLS certificate.
func FetchTlsCertSha256(requestJSON string) string {
	return fetchCertSha256(requestJSON, fetchTLSCertSha256)
}

// FetchQuicCertSha256 extracts the SHA-256 fingerprint of a remote server's QUIC/HTTP3 certificate.
func FetchQuicCertSha256(requestJSON string) string {
	return fetchCertSha256(requestJSON, fetchQUICCertSha256)
}

func fetchCertSha256(
	requestJSON string,
	fetcher func(certSha256Request) (string, error),
) string {
	var request certSha256Request
	if err := json.Unmarshal([]byte(requestJSON), &request); err != nil {
		return marshalCertSha256Result(certSha256Result{Error: err.Error()})
	}

	sha256Value, err := fetcher(request)
	if err != nil {
		return marshalCertSha256Result(certSha256Result{Error: err.Error()})
	}

	return marshalCertSha256Result(certSha256Result{Sha256: sha256Value})
}

func fetchTLSCertSha256(request certSha256Request) (string, error) {
	address, serverName, timeout, err := normalizeCertRequest(request)
	if err != nil {
		return "", err
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp",
		address,
		&tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("peer certificate is empty")
	}

	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

func fetchQUICCertSha256(request certSha256Request) (string, error) {
	address, serverName, timeout, err := normalizeCertRequest(request)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := quic.DialAddr(
		ctx,
		address,
		&tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h3"},
		},
		&quic.Config{
			HandshakeIdleTimeout: timeout,
			MaxIdleTimeout:       timeout,
		},
	)
	if err != nil {
		return "", err
	}
	defer conn.CloseWithError(0, "")

	state := conn.ConnectionState()
	if len(state.TLS.PeerCertificates) == 0 {
		return "", errors.New("peer certificate is empty")
	}

	sum := sha256.Sum256(state.TLS.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeCertRequest(req certSha256Request) (string, string, time.Duration, error) {
	if req.Address == "" {
		return "", "", 0, errors.New("address is empty")
	}

	port := req.Port
	if port <= 0 {
		port = 443
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	return net.JoinHostPort(req.Address, strconv.Itoa(port)), req.ServerName, timeout, nil
}

func marshalCertSha256Result(result certSha256Result) string {
	data, err := json.Marshal(result)
	if err != nil {
		return `{"error":"failed to marshal result"}`
	}
	return string(data)
}

// MemoryStats holds detailed metrics on Go runtime and core memory usage.
type MemoryStats struct {
	AllocBytes    int64  `json:"allocBytes"`
	AllocMb       string `json:"allocMb"`
	TotalAlloc    int64  `json:"totalAlloc"`
	SysBytes      int64  `json:"sysBytes"`
	SysMb         string `json:"sysMb"`
	HeapInuse     int64  `json:"heapInuse"`
	HeapIdle      int64  `json:"heapIdle"`
	HeapReleased  int64  `json:"heapReleased"`
	NumGoroutines int    `json:"numGoroutines"`
	NumGC         uint32 `json:"numGc"`
}

// ReadMemoryStats returns the current memory usage of the Go runtime and tunnel core as a JSON string.
func ReadMemoryStats() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	stats := MemoryStats{
		AllocBytes:    int64(m.Alloc),
		AllocMb:       fmt.Sprintf("%.2f MB", float64(m.Alloc)/(1024*1024)),
		TotalAlloc:    int64(m.TotalAlloc),
		SysBytes:      int64(m.Sys),
		SysMb:         fmt.Sprintf("%.2f MB", float64(m.Sys)/(1024*1024)),
		HeapInuse:     int64(m.HeapInuse),
		HeapIdle:      int64(m.HeapIdle),
		HeapReleased:  int64(m.HeapReleased),
		NumGoroutines: runtime.NumGoroutine(),
		NumGC:         m.NumGC,
	}
	data, err := json.Marshal(stats)
	if err != nil {
		return `{"error":"failed to marshal memory stats"}`
	}
	return string(data)
}

// ForceFreeMemory triggers a garbage collection cycle and releases unused memory back to the OS.
func ForceFreeMemory() {
	debug.FreeOSMemory()
}

