// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"fmt"
	"log"
	"os"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	browser_dialer "github.com/xtls/xray-core/transport/internet/browser_dialer"

	"github.com/ZloyRadetski/skipi-core/internal/assets"
	"github.com/ZloyRadetski/skipi-core/internal/runtimetuning"
)

// Process-wide environment variable names Xray reads.
const (
	coreAsset            = "xray.location.asset"
	coreCert             = "xray.location.cert"
	v2rayAsset           = "v2ray.location.asset"
	xudpBaseKey          = "xray.xudp.basekey"
	tunFdKey             = "xray.tun.fd"
	v2rayTunFdKey        = "v2ray.tun.fd"
	browserDialerAddress = "xray.browser.dialer"
)

// init applies the mobile-first Go runtime profile before any core starts; see runtimetuning.Init.
func init() {
	runtimetuning.Init()
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

// clearTunFdEnv removes the process-wide TUN descriptor published for a core start.
func clearTunFdEnv() {
	unsetEnvVariable(tunFdKey)
	unsetEnvVariable(v2rayTunFdKey)
}

// InitCoreEnv configures environment variables (assets and certificate path) and installs
// the host-appropriate Xray asset reader. Android may fall back to APK assets; desktop
// hosts intentionally use only the configured filesystem directory.
func InitCoreEnv(dataDir string, assetKey string) {
	if len(dataDir) > 0 {
		setEnvVariable(coreAsset, dataDir)
		setEnvVariable(coreCert, dataDir)
		setEnvVariable(v2rayAsset, dataDir)
	}
	if len(assetKey) > 0 {
		setEnvVariable(xudpBaseKey, assetKey)
	}
	assets.Configure()
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
