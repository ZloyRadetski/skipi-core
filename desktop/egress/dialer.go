// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package egress owns how SKIPI Core's own connections leave the computer. It puts one system dialer in place
// for Xray, in front of Xray's default one. Off, or with fewer than two usable links, every dial goes to Xray's
// dialer unchanged. With link merging on, each new connection to the internet is given one of the links: its
// name in a copy of the socket options (Xray pins the socket to it) and, for an IP destination, its address as
// the source. A link that cannot reach the network is left for another one within the same dial.
package egress

import (
	"context"
	"net/netip"
	"sync/atomic"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

// Dialer is an internet.SystemDialer that spreads new connections over the links of a multilink.Scheduler.
type Dialer struct {
	base  internet.SystemDialer
	sched atomic.Pointer[multilink.Scheduler]
}

// NewDialer puts the dialer in front of base, with merging off.
func NewDialer(base internet.SystemDialer) *Dialer { return &Dialer{base: base} }

// SetScheduler switches merging on with these links, or off with nil. Only dials that start afterwards see it:
// connections already open stay on the link they were given.
func (d *Dialer) SetScheduler(s *multilink.Scheduler) { d.sched.Store(s) }

// Scheduler is the scheduler in use, nil while merging is off.
func (d *Dialer) Scheduler() *multilink.Scheduler { return d.sched.Load() }

func (d *Dialer) DestIpAddress() net.IP { return d.base.DestIpAddress() }

func (d *Dialer) Dial(ctx context.Context, src net.Address, dest net.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	sched := d.sched.Load()
	family, ok := mergeable(src, dest, sockopt)
	if !ok || sched == nil || ctx.Value(withoutMergingKey{}) != nil || sched.Usable(family) < 2 {
		return d.base.Dial(ctx, src, dest, sockopt)
	}
	tried := map[string]struct{}{}
	var lastErr error
	for {
		sl := sched.AcquireFor(family, tried)
		if sl == nil {
			return nil, lastErr
		}
		tried[sl.Key()] = struct{}{}
		var conn net.Conn
		var err error
		if sl.Handle() != 0 {
			conn, err = dialBound(ctx, sl, family, dest, sockopt)
		} else {
			pinned := pinnedOptions(sockopt, sl.Name)
			var from net.Address
			if dest.Address.Family().IsIP() {
				from = net.IPAddress(sl.IP(family))
			}
			conn, err = d.base.Dial(ctx, from, dest, pinned)
		}
		if err == nil {
			if dest.Network == net.Network_UDP {
				// A UDP socket holds no balancing slot (DNS makes them short and many), and it is handed back as the
				// type Xray made: transports assert it, and quic-go needs the bare socket for GSO.
				sched.ReleaseFor(sl, family)
				return conn, nil
			}
			return sched.Open(conn, sl, family), nil
		}
		sched.ReleaseFor(sl, family)
		retry, linkDown := multilink.Classify(err)
		if linkDown {
			sched.Fail(sl, family, multilink.FailCooldown)
		} else if retry {
			sched.Suspect(sl, family)
		}
		lastErr = err
		if !retry || ctx.Err() != nil {
			return nil, err
		}
	}
}

// pinnedOptions copies the caller's socket options with the link named, so the caller's own stay untouched.
func pinnedOptions(sockopt *internet.SocketConfig, link string) *internet.SocketConfig {
	pinned := &internet.SocketConfig{}
	if sockopt != nil {
		pinned = proto.Clone(sockopt).(*internet.SocketConfig)
	}
	pinned.Interface = link
	return pinned
}

// mergeable reports whether a dial may be given a link, and the address family that decides which links can take
// it. Not when something already chose the way out (a sockopt interface, a sendThrough address), and not for a
// destination that is not on the internet: the LAN, loopback, link-local, multicast and the TUN's fake range must
// keep following the system's routes.
func mergeable(src net.Address, dest net.Destination, sockopt *internet.SocketConfig) (multilink.Family, bool) {
	if dest.Network != net.Network_TCP && dest.Network != net.Network_UDP {
		return multilink.Fam4, false
	}
	if sockopt != nil && sockopt.Interface != "" {
		return multilink.Fam4, false
	}
	if src != nil && src != net.AnyIP && src != net.AnyIPv6 {
		return multilink.Fam4, false
	}
	if dest.Address == nil {
		return multilink.Fam4, false
	}
	if dest.Address.Family().IsDomain() {
		return multilink.Fam4, true
	}
	addr, ok := netip.AddrFromSlice(dest.Address.IP())
	if !ok {
		return multilink.Fam4, false
	}
	addr = addr.Unmap()
	if !onInternet(addr) {
		return multilink.Fam4, false
	}
	if addr.Is6() {
		return multilink.Fam6, true
	}
	return multilink.Fam4, true
}

var notInternet = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT, also Tailscale's peers
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking: TUN addresses and fake DNS answers
	netip.MustParsePrefix("0.0.0.0/8"),
}

func onInternet(addr netip.Addr) bool {
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, prefix := range notInternet {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

var _ internet.SystemDialer = (*Dialer)(nil)

type withoutMergingKey struct{}

// WithoutMerging marks a dial that must take the way Xray's own dialer takes, whether merging is on or not: a
// latency measurement that should not jump between the links' paths.
func WithoutMerging(ctx context.Context) context.Context {
	return context.WithValue(ctx, withoutMergingKey{}, true)
}
