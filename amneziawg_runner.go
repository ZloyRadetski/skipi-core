// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// AmneziaWgRunner manages the lifecycle of an AmneziaWG netstack tunnel with a local SOCKS5 listener.
type AmneziaWgRunner struct {
	mu         sync.Mutex
	tun        tun.Device
	dev        *device.Device
	bind       conn.Bind
	tnet       *netstack.Net
	localAddrs []netip.Addr
	listener   net.Listener
	socksPort  int
	running    bool
	cancel     context.CancelFunc
	protector  SocketProtector
	// sessionOwned marks the runner of a session; the public start and stop leave it alone.
	sessionOwned bool
	// socksUser and socksPass, when set, are required from every SOCKS client.
	socksUser, socksPass string
	// socksConns counts the SOCKS connections being served (see maxSocksConns).
	socksConns atomic.Int32

	dnsMu    sync.Mutex
	dnsCache map[string]tunnelDNSEntry
}

// requireAwgProtector is true where Core always runs inside a VPN (Android): a runner without a
// protector does not start there. A variable so tests can set it.
var requireAwgProtector = runtime.GOOS == "android"

// NewAmneziaWgRunner builds an AmneziaWgRunner instance from parsed settings.
func NewAmneziaWgRunner(settings *AmneziaWgSettings, socksPort int) (*AmneziaWgRunner, error) {
	if socksPort <= 0 {
		socksPort = 10809
	}
	if err := settings.validateNativeRunnerCompatibility(); err != nil {
		return nil, err
	}
	dnsAddrs, err := settings.netstackDNSAddresses()
	if err != nil {
		return nil, err
	}
	protector := currentAmneziaWgSocketProtector()
	if protector == nil && requireAwgProtector {
		// Inside a VPN the peer's packets would enter the tunnel they carry and never arrive.
		return nil, errors.New("AmneziaWG needs a socket protector here; none is registered")
	}
	// The UAPI endpoint parser accepts address literals only. Resolve a domain
	// before IpcSet rather than passing an opaque hostname through to it.
	if err := settings.resolvePeerEndpoints(dnsAddrs, protector); err != nil {
		return nil, err
	}

	var localAddrs []netip.Addr
	switch addrVal := settings.Address.(type) {
	case string:
		if prefix, err := netip.ParsePrefix(addrVal); err == nil {
			localAddrs = append(localAddrs, prefix.Addr())
		} else if addr, err := netip.ParseAddr(addrVal); err == nil {
			localAddrs = append(localAddrs, addr)
		}
	case []any:
		for _, a := range addrVal {
			if str, ok := a.(string); ok {
				if prefix, err := netip.ParsePrefix(str); err == nil {
					localAddrs = append(localAddrs, prefix.Addr())
				} else if addr, err := netip.ParseAddr(str); err == nil {
					localAddrs = append(localAddrs, addr)
				}
			}
		}
	}
	if len(localAddrs) == 0 {
		localAddrs = []netip.Addr{netip.MustParseAddr("10.8.0.2")}
	}

	mtu := settings.MTU
	if mtu <= 0 {
		mtu = 1420
	}

	tunDev, tnet, err := netstack.CreateNetTUN(localAddrs, dnsAddrs, mtu)
	if err != nil {
		return nil, fmt.Errorf("create netstack tun: %w", err)
	}

	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {},
		Errorf:   func(format string, args ...any) {},
	}

	bind := conn.NewDefaultBind()
	dev := device.NewDevice(tunDev, bind, logger)

	ipcString, err := settings.BuildIpcConfig()
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("build ipc config: %w", err)
	}

	if err := dev.IpcSet(ipcString); err != nil {
		dev.Close()
		return nil, fmt.Errorf("device IpcSet failed: %w", err)
	}

	return &AmneziaWgRunner{
		tun:        tunDev,
		dev:        dev,
		bind:       bind,
		tnet:       tnet,
		localAddrs: append([]netip.Addr(nil), localAddrs...),
		socksPort:  socksPort,
		protector:  protector,
		socksUser:  settings.SocksUser,
		socksPass:  settings.SocksPass,
	}, nil
}

// Start brings up the AmneziaWG device and listens on the local SOCKS5 port.
func (r *AmneziaWgRunner) Start() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return nil
	}

	if err := r.dev.Up(); err != nil {
		r.dev.Close()
		return fmt.Errorf("device Up failed: %w", err)
	}
	if err := r.protectPeerSockets(); err != nil {
		r.dev.Close()
		return err
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", r.socksPort))
	if err != nil {
		r.dev.Close()
		return fmt.Errorf("listen on socks port %d: %w", r.socksPort, err)
	}
	r.listener = ln
	r.socksPort = ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.running = true

	go r.serveSocks(ctx, ln)
	return nil
}

// protectPeerSockets asks Android to exclude the WireGuard peer sockets from
// the VPN TUN. The sockets only exist after device.Up(). The Android app
// requires this bridge for active VPN sessions; standalone use has no TUN.
func (r *AmneziaWgRunner) protectPeerSockets() error {
	if r.protector == nil {
		// Standalone use (for example, a pre-VPN latency check) has no Android
		// TUN to escape. The Android app enforces a registered protector before
		// it starts this runner as part of an active VPN session.
		return nil
	}

	peek, ok := r.bind.(conn.PeekLookAtSocketFd)
	if !ok {
		if runtime.GOOS == "android" {
			return errors.New("amneziawg bind does not expose peer socket descriptors")
		}
		return nil
	}

	protected := 0
	for _, getFD := range []func() (int, error){peek.PeekLookAtSocketFd4, peek.PeekLookAtSocketFd6} {
		fd, err := getFD()
		if err != nil || fd < 0 {
			continue
		}
		if !r.protector.Protect(fd) {
			return fmt.Errorf("VpnService.protect rejected AmneziaWG socket fd %d", fd)
		}
		protected++
	}
	if protected == 0 && runtime.GOOS == "android" {
		return errors.New("could not protect any AmneziaWG peer sockets")
	}
	return nil
}

// Stop terminates the SOCKS5 server and shuts down the AmneziaWG device.
func (r *AmneziaWgRunner) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}
	r.running = false

	if r.cancel != nil {
		r.cancel()
	}
	if r.listener != nil {
		_ = r.listener.Close()
		r.listener = nil
	}
	if r.dev != nil {
		r.dev.Close()
		r.dev = nil
	} else if r.tun != nil {
		_ = r.tun.Close()
	}
	r.tun = nil
	return nil
}
