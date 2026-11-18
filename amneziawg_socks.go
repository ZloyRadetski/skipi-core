// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// socksHandshakeTimeout bounds greeting and request: a local client that connects and then
	// stays silent must not hold a goroutine for the life of the runner.
	socksHandshakeTimeoutDefault = 10 * time.Second
	// socksHalfCloseTimeout is how long the other direction may keep going once one has ended.
	socksHalfCloseTimeout = 30 * time.Second
	socksLookupTimeout    = 5 * time.Second

	socksCopyBufferSize = 32 * 1024
	socksUDPBufferSize  = 64 * 1024

	tunnelDNSCacheTTL     = 30 * time.Second
	tunnelDNSCacheEntries = 256
)

var (
	socksCopyBuffers = sync.Pool{New: func() any { b := make([]byte, socksCopyBufferSize); return &b }}
	socksUDPBuffers  = sync.Pool{New: func() any { b := make([]byte, socksUDPBufferSize); return &b }}
)

// copyPooled copies src to dst through a pooled buffer. The wrappers hide ReadFrom/WriteTo so
// the supplied buffer is really used instead of a fresh 32 KiB one per call.
func copyPooled(dst io.Writer, src io.Reader) error {
	buf := socksCopyBuffers.Get().(*[]byte)
	defer socksCopyBuffers.Put(buf)
	_, err := io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, *buf)
	return err
}

type closeWriter interface{ CloseWrite() error }

// relay moves bytes both ways until both directions end. When one direction finishes cleanly its
// write side is shut down so the peer sees EOF and may still finish its answer; a failed copy, a
// cancelled ctx or the grace period after the first direction ends closes both connections.
func relay(ctx context.Context, a, b net.Conn) {
	type result struct{ err error }
	done := make(chan result, 2)
	pipe := func(dst, src net.Conn) {
		err := copyPooled(dst, src)
		if cw, ok := dst.(closeWriter); ok && err == nil {
			_ = cw.CloseWrite()
		}
		done <- result{err}
	}
	go pipe(b, a)
	go pipe(a, b)

	defer func() {
		_ = a.Close()
		_ = b.Close()
	}()
	var grace <-chan time.Time
	for finished := 0; finished < 2; {
		select {
		case r := <-done:
			finished++
			if r.err != nil {
				return
			}
			if finished == 1 {
				timer := time.NewTimer(socksHalfCloseTimeout)
				defer timer.Stop()
				grace = timer.C
			}
		case <-grace:
			return
		case <-ctx.Done():
			return
		}
	}
}

type tunnelDNSEntry struct {
	addr    string
	expires time.Time
}

// lookupTunnelHost resolves a name through the tunnel's DNS with the caller's deadline. Answers
// are cached briefly: Xray repeats a domain for every datagram of a UDP flow, and each uncached
// lookup would otherwise stall the association's single reader.
func (r *AmneziaWgRunner) lookupTunnelHost(ctx context.Context, host string) (net.IP, error) {
	now := time.Now()
	r.dnsMu.Lock()
	entry, ok := r.dnsCache[host]
	r.dnsMu.Unlock()
	if ok && now.Before(entry.expires) {
		return net.ParseIP(entry.addr), nil
	}

	ctx, cancel := context.WithTimeout(ctx, socksLookupTimeout)
	defer cancel()
	addrs, err := r.tnet.LookupContextHost(ctx, host)
	if err != nil {
		return nil, err
	}
	var chosen net.IP
	for _, text := range addrs {
		ip := net.ParseIP(text)
		if ip == nil {
			continue
		}
		if chosen == nil {
			chosen = ip
		}
		// Prefer a family the tunnel has an address for; the first answer may be unreachable.
		if r.hasLocalFamily(ip) {
			chosen = ip
			break
		}
	}
	if chosen == nil {
		return nil, errNoTunnelAddress
	}

	r.dnsMu.Lock()
	if r.dnsCache == nil || len(r.dnsCache) >= tunnelDNSCacheEntries {
		r.dnsCache = make(map[string]tunnelDNSEntry)
	}
	r.dnsCache[host] = tunnelDNSEntry{addr: chosen.String(), expires: now.Add(tunnelDNSCacheTTL)}
	r.dnsMu.Unlock()
	return chosen, nil
}

func (r *AmneziaWgRunner) hasLocalFamily(ip net.IP) bool {
	is4 := ip.To4() != nil
	for _, local := range r.localAddrs {
		if local.Unmap().Is4() == is4 {
			return true
		}
	}
	return false
}

// socksHandshakeTimeout is a variable so tests can shorten it.
var socksHandshakeTimeout = socksHandshakeTimeoutDefault
