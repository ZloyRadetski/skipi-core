// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// CoreCallbackHandler handles lifecycle and logging events from the core.
type CoreCallbackHandler interface {
	Startup() int64
	Shutdown() int64
	OnEmitStatus(code int64, message string) int64
}

// CoreController manages the lifecycle of an Xray-core instance.
type CoreController struct {
	mu        sync.Mutex
	instance  *core.Instance
	callback  CoreCallbackHandler
	isRunning bool
}

// NewCoreController creates a new CoreController with the provided callback handler.
func NewCoreController(handler CoreCallbackHandler) *CoreController {
	return &CoreController{
		callback: handler,
	}
}

// StartLoop initializes and starts the Xray core instance with given JSON config.
func (c *CoreController) StartLoop(configJSON string, tunFd int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isRunning {
		return errors.New("core instance is already running")
	}

	if tunFd > 0 {
		fdStr := strconv.FormatInt(tunFd, 10)
		_ = os.Setenv("xray.tun.fd", fdStr)
		_ = os.Setenv("v2ray.tun.fd", fdStr)
	} else {
		_ = os.Unsetenv("xray.tun.fd")
		_ = os.Unsetenv("v2ray.tun.fd")
	}

	config, err := core.LoadConfig("json", strings.NewReader(configJSON))
	if err != nil {
		return fmt.Errorf("failed to load xray config: %w", err)
	}

	server, err := core.New(config)
	if err != nil {
		return fmt.Errorf("failed to create xray instance: %w", err)
	}

	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start xray instance: %w", err)
	}

	c.instance = server
	c.isRunning = true

	if c.callback != nil {
		c.callback.Startup()
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
	c.isRunning = false

	if c.callback != nil {
		c.callback.Shutdown()
	}

	return err
}

// IsRunning returns whether the core instance is currently running.
func (c *CoreController) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isRunning
}

// InitCoreEnv configures environment variables (assets and certificate path) for Xray.
func InitCoreEnv(dataDir string, assetKey string) {
	if dataDir != "" {
		_ = os.Setenv("xray.location.asset", dataDir)
		_ = os.Setenv("xray.location.cert", dataDir)
		_ = os.Setenv("v2ray.location.asset", dataDir)
	}
	if assetKey != "" {
		_ = os.Setenv("xray.xudp.basekey", assetKey)
	}
}

// CoreVersion returns the version of the underlying Xray-core engine.
func CoreVersion() string {
	return core.Version()
}

// MeasureOutboundDelay tests the latency of an outbound proxy configuration against a target URL.
func MeasureOutboundDelay(configJSON string, targetURL string) (int64, error) {
	if targetURL == "" {
		targetURL = "https://www.google.com/generate_204"
	}

	config, err := core.LoadConfig("json", strings.NewReader(configJSON))
	if err != nil {
		return -1, fmt.Errorf("failed to parse test config: %w", err)
	}

	server, err := core.New(config)
	if err != nil {
		return -1, fmt.Errorf("failed to create test instance: %w", err)
	}

	if err := server.Start(); err != nil {
		return -1, fmt.Errorf("failed to start test instance: %w", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := xnet.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			return core.Dial(ctx, server, dest)
		},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return -1, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	elapsed := time.Since(start).Milliseconds()
	return elapsed, nil
}
