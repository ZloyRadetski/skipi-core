// Based on net-merge (https://github.com/net-merge/net-merge), Copyright (c) 2026 Rohit Mahto, MIT License;
// see third_party/net-merge. Changes for SKIPI Core: Copyright 2026, Radetski, GPL-3.0.

package multilink

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// udpFlowActivity tracks per-socket UDP packet statistics within an active burst window to detect real-time game or voice traffic.
type udpFlowActivity struct {
	mu                        sync.Mutex
	started, lastActive       time.Time
	packets, smallPkts, bytes int64

	app     *appPeers // shared by every socket of the same application port
	appPort uint16
}

// appPeers is who one application port talks to, over the current and the last peerWindow.
type appPeers struct {
	sockets int // guarded by Scheduler.mu

	mu    sync.Mutex
	peers map[netip.AddrPort]struct{}
	since time.Time
	last  int
}

func (p *appPeers) add(peer netip.AddrPort, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if now.Sub(p.since) > peerWindow {
		p.last, p.peers, p.since = len(p.peers), nil, now
	}
	if len(p.peers) <= gamePeers {
		if p.peers == nil {
			p.peers = map[netip.AddrPort]struct{}{}
		}
		p.peers[peer] = struct{}{}
	}
}

func (p *appPeers) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return max(len(p.peers), p.last)
}

// A game or call talks to a few peers. A torrent client's DHT sends the same kind of small, steady
// packets to hundreds. ponytail: a fixed cut-off; raise it if a peer-to-peer game is missed.
const (
	gamePeers  = 16
	peerWindow = 10 * time.Second
)

func (u *udpFlowActivity) record(n int, addr net.Addr, now time.Time) {
	// Skip non-game/background protocols per packet so a single DNS/QUIC probe does not permanently taint the socket.
	if ua, ok := addr.(*net.UDPAddr); ok && (ua.Port == 53 || ua.Port == 123 || ua.Port == 443 || ua.Port == 5353) {
		return
	}
	u.mu.Lock()
	// Start a fresh activity window on the first valid packet or after >3s of idle time.
	if u.started.IsZero() || now.Sub(u.lastActive) > 3*time.Second {
		u.started = now
		u.packets = 0
		u.smallPkts = 0
		u.bytes = 0
	}
	if ua, ok := addr.(*net.UDPAddr); ok {
		if u.app == nil {
			u.app = &appPeers{}
		}
		u.app.add(ua.AddrPort(), now)
	}
	if now.After(u.lastActive) {
		u.lastActive = now
	}
	u.packets++
	u.bytes += int64(n)
	if n < 600 {
		u.smallPkts++
	}
	u.mu.Unlock()
}

// isGameLike reports whether the current active window sustains a low-bandwidth, steady stream of small UDP packets (>=5s, >=5 pkts/s, >=50% <600B, <1Mbps).
func (u *udpFlowActivity) isGameLike(now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.started.IsZero() || now.Sub(u.lastActive) > 3*time.Second {
		return false
	}
	if u.app != nil && u.app.count() > gamePeers {
		return false
	}
	dur := now.Sub(u.started).Seconds()
	if dur < 5 {
		return false
	}
	pkts, small := float64(u.packets), float64(u.smallPkts)
	return pkts/dur >= 5 && small >= 0.5*pkts && float64(u.bytes)*8/dur < 1_000_000
}
