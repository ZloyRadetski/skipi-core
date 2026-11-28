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
	"sync"
	"sync/atomic"
	"time"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

// Dialer is an internet.SystemDialer that spreads new connections over the links of a multilink.Scheduler.
type Dialer struct {
	base  internet.SystemDialer
	sched atomic.Pointer[multilink.Scheduler]
	// acquire picks the link for a dial; nil takes the scheduler's own pick (a seam for tests).
	acquire func(multilink.Family, []string) *multilink.Slot

	// pins caches the socket options copied for a link (see pinned), so a dial does not clone them again.
	pinMu sync.Mutex
	pins  map[pinKey]*internet.SocketConfig
}

type pinKey struct {
	opt       *internet.SocketConfig
	link      string
	keepAlive time.Duration
}

// maxPins bounds the cache: socket options come from the config, a handful per outbound, so it only fills up when
// the config is replaced over and over.
const maxPins = 64

// attemptTimeout is how long one link gets to connect while another is left to try; the last link gets the whole
// connect budget, as an unmerged dial does.
var attemptTimeout = 4 * time.Second

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
	if sched == nil {
		return d.base.Dial(ctx, src, dest, sockopt)
	}
	family, ok := mergeable(src, dest, sockopt)
	if !ok || ctx.Value(withoutMergingKey{}) != nil {
		return d.base.Dial(ctx, src, dest, sockopt)
	}
	var usable int
	var first *multilink.Slot // the pick made together with the count
	acquire := d.acquire
	if acquire == nil {
		acquire = sched.AcquireFor
		first, usable = sched.AcquireUsable(family, 2, nil)
	} else {
		usable = sched.Usable(family)
	}
	if usable < 2 {
		return d.base.Dial(ctx, src, dest, sockopt)
	}
	var triedBuf [4]string
	tried := triedBuf[:0]
	var lastErr error
	for {
		sl := first
		first = nil
		if sl == nil {
			sl = acquire(family, tried)
		}
		if sl == nil {
			if lastErr == nil {
				return d.base.Dial(ctx, src, dest, sockopt)
			}
			return nil, lastErr
		}
		tried = append(tried, sl.Key())
		// While another link is left, a link that does not answer is given up on early.
		attemptCtx, cancel := ctx, context.CancelFunc(func() {})
		if len(tried) < usable {
			attemptCtx, cancel = context.WithTimeout(ctx, attemptTimeout)
		}
		keepAlive := sched.PhoneKeepAlive(sl)
		var conn net.Conn
		var err error
		if sl.Handle() != 0 || bindsLinkItself() {
			conn, err = dialBound(attemptCtx, sl, family, dest, sockopt, keepAlive)
		} else {
			pinned := d.pinned(sockopt, sl.Name, keepAlive)
			var from net.Address
			if dest.Address.Family().IsIP() {
				from = net.IPAddress(sl.IP(family))
			}
			conn, err = d.base.Dial(attemptCtx, from, dest, pinned)
		}
		cancel()
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

// pinned is the caller's socket options with the link named (and, for a phone, its keep-alive period), as a copy so
// the caller's own stay untouched. The copy is kept per (options, link, period): Xray's options are fixed once the
// config is loaded, and cloning them with reflection on every dial is the dearest thing a merged dial does itself.
func (d *Dialer) pinned(sockopt *internet.SocketConfig, link string, keepAlive time.Duration) *internet.SocketConfig {
	key := pinKey{sockopt, link, keepAlive}
	d.pinMu.Lock()
	defer d.pinMu.Unlock()
	if p, ok := d.pins[key]; ok {
		return p
	}
	pinned := &internet.SocketConfig{}
	if sockopt != nil {
		pinned = proto.Clone(sockopt).(*internet.SocketConfig)
	}
	pinned.Interface = link
	if keepAlive > 0 && pinned.TcpKeepAliveIdle >= 0 && pinned.TcpKeepAliveInterval >= 0 {
		pinned.TcpKeepAliveIdle = int32(keepAlive / time.Second)
		pinned.TcpKeepAliveInterval = int32(keepAlive / time.Second)
	}
	if d.pins == nil || len(d.pins) >= maxPins {
		d.pins = make(map[pinKey]*internet.SocketConfig)
	}
	d.pins[key] = pinned
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
