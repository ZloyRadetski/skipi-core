// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package egress

import (
	"context"
	"syscall"
	"time"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// dialBound dials over a link the host owns (Android's networks): the socket is bound to the link by its handle
// before it connects, which an interface name given to Xray's dialer cannot do there. It makes the socket the way
// Xray's own dialer does, minus the options that need the system to allow them.
func dialBound(ctx context.Context, sl *multilink.Slot, family multilink.Family, dest net.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	control := sl.Control(family == multilink.Fam6)
	if dest.Network == net.Network_UDP {
		destAddr, err := net.ResolveUDPAddr("udp", dest.NetAddr())
		if err != nil {
			return nil, err
		}
		wildcard := net.AnyIP.IP()
		if destAddr.IP.To4() == nil {
			wildcard = net.AnyIPv6.IP()
		}
		lc := net.ListenConfig{Control: func(network, _ string, c syscall.RawConn) error {
			return control(network, destAddr.String(), c)
		}}
		packetConn, err := lc.ListenPacket(ctx, "udp", (&net.UDPAddr{IP: wildcard}).String())
		if err != nil {
			return nil, err
		}
		return &net.PacketConnWrapper{PacketConn: packetConn, Dest: destAddr}, nil
	}
	keepAlive := net.KeepAliveConfig{Enable: true, Idle: 45 * time.Second, Interval: 45 * time.Second, Count: -1}
	var keepAliveDuration time.Duration
	if sockopt != nil {
		if sockopt.TcpKeepAliveIdle < 0 || sockopt.TcpKeepAliveInterval < 0 {
			keepAliveDuration = -1
			keepAlive.Enable = false
		}
		if sockopt.TcpKeepAliveIdle > 0 {
			keepAlive.Idle = time.Duration(sockopt.TcpKeepAliveIdle) * time.Second
		}
		if sockopt.TcpKeepAliveInterval > 0 {
			keepAlive.Interval = time.Duration(sockopt.TcpKeepAliveInterval) * time.Second
		}
	}
	dialer := &net.Dialer{Timeout: 16 * time.Second, KeepAlive: keepAliveDuration, KeepAliveConfig: keepAlive, Control: control}
	return dialer.DialContext(ctx, dest.Network.SystemString(), dest.NetAddr())
}
