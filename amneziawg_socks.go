// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ZloyRadetski/skipi-core/internal/amneziawg"
)

// The local SOCKS5 bridge of AmneziaWgRunner: methods of the bound runner type, using the wire
// helpers of internal/amneziawg.

const (
	// socksHandshakeTimeout bounds greeting and request: a local client that connects and then
	// stays silent must not hold a goroutine for the life of the runner.
	socksHandshakeTimeoutDefault = 10 * time.Second
	socksLookupTimeout           = 5 * time.Second

	tunnelDNSCacheTTL     = 30 * time.Second
	tunnelDNSCacheEntries = 256
)

// socksHandshakeTimeout is a variable so tests can shorten it.
var socksHandshakeTimeout = socksHandshakeTimeoutDefault

var errNoTunnelAddress = errors.New("lookup through AmneziaWG returned no usable address")

type tunnelDNSEntry struct {
	addr    string
	err     error // a failed lookup, remembered for tunnelDNSNegativeTTL
	expires time.Time
}

// tunnelDNSCall is one lookup in flight; callers asking for the same name wait on it.
type tunnelDNSCall struct {
	done chan struct{}
	ip   net.IP
	err  error
}

// tunnelDNSNegativeTTL is a variable so tests can shorten it.
var tunnelDNSNegativeTTL = 5 * time.Second

// lookupTunnelHost resolves a name through the tunnel's DNS. Answers are cached briefly: Xray
// repeats a domain for every datagram of a UDP flow, and each uncached lookup would otherwise
// stall the association's single reader. Failures are cached too (a dead name would cost the full
// lookup timeout on every datagram), and callers asking for one name share a single query. The
// query runs under its own timeout, so a caller that gives up never cancels it for the others.
func (r *AmneziaWgRunner) lookupTunnelHost(ctx context.Context, host string) (net.IP, error) {
	r.dnsMu.Lock()
	if entry, ok := r.dnsCache[host]; ok && time.Now().Before(entry.expires) {
		r.dnsMu.Unlock()
		if entry.err != nil {
			return nil, entry.err
		}
		return net.ParseIP(entry.addr), nil
	}
	call, inFlight := r.dnsFlight[host]
	if !inFlight {
		if r.dnsFlight == nil {
			r.dnsFlight = make(map[string]*tunnelDNSCall)
		}
		call = &tunnelDNSCall{done: make(chan struct{})}
		r.dnsFlight[host] = call
		go r.runTunnelLookup(host, call)
	}
	r.dnsMu.Unlock()

	select {
	case <-call.done:
		return call.ip, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *AmneziaWgRunner) runTunnelLookup(host string, call *tunnelDNSCall) {
	ctx, cancel := context.WithTimeout(context.Background(), socksLookupTimeout)
	defer cancel()
	call.ip, call.err = r.resolveTunnelHost(ctx, host)

	entry := tunnelDNSEntry{err: call.err}
	if call.err == nil {
		entry.addr = call.ip.String()
		entry.expires = time.Now().Add(tunnelDNSCacheTTL)
	} else {
		entry.expires = time.Now().Add(tunnelDNSNegativeTTL)
	}
	r.dnsMu.Lock()
	r.storeTunnelDNSLocked(host, entry)
	delete(r.dnsFlight, host)
	r.dnsMu.Unlock()
	close(call.done)
}

// storeTunnelDNSLocked caches entry. A full cache gives up the entry that expires first, not
// everything: dropping all of it would send every active name to the resolver at once.
func (r *AmneziaWgRunner) storeTunnelDNSLocked(host string, entry tunnelDNSEntry) {
	if r.dnsCache == nil {
		r.dnsCache = make(map[string]tunnelDNSEntry)
	}
	if _, exists := r.dnsCache[host]; !exists && len(r.dnsCache) >= tunnelDNSCacheEntries {
		var oldest string
		var oldestExpiry time.Time
		first := true
		for k, e := range r.dnsCache {
			if first || e.expires.Before(oldestExpiry) {
				oldest, oldestExpiry, first = k, e.expires, false
			}
		}
		delete(r.dnsCache, oldest)
	}
	r.dnsCache[host] = entry
}

func (r *AmneziaWgRunner) resolveTunnelHost(ctx context.Context, host string) (net.IP, error) {
	lookup := r.lookupHost
	if lookup == nil {
		lookup = r.tnet.LookupContextHost
	}
	addrs, err := lookup(ctx, host)
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

// serveSocks accepts inbound SOCKS5 connections from local applications or Xray.
func (r *AmneziaWgRunner) serveSocks(ctx context.Context, ln net.Listener) {
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(20 * time.Millisecond)
				continue
			}
		}
		// Every connection holds a goroutine and, once dialed, netstack buffers: past the limit a
		// local client is turned away instead of growing the process without bound.
		if int(r.socksConns.Add(1)) > maxSocksConns {
			r.socksConns.Add(-1)
			_ = clientConn.Close()
			continue
		}
		go func() {
			defer r.socksConns.Add(-1)
			r.handleSocksConn(ctx, clientConn)
		}()
	}
}

// maxSocksConns bounds the SOCKS connections a runner serves at once. A variable so tests can lower it.
var maxSocksConns = 1024

// socksAuthenticate runs the method negotiation and, when the runner has credentials, the
// username/password exchange of RFC 1929. It reports whether the client may go on.
func (r *AmneziaWgRunner) socksAuthenticate(c net.Conn, methods []byte) bool {
	if r.socksUser == "" && r.socksPass == "" {
		_, err := c.Write([]byte{0x05, 0x00}) // no authentication required
		return err == nil
	}
	if !bytes.Contains(methods, []byte{0x02}) {
		_, _ = c.Write([]byte{0x05, 0xff}) // no acceptable method
		return false
	}
	if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
		return false
	}
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil || head[0] != 0x01 {
		return false
	}
	user := make([]byte, head[1])
	if _, err := io.ReadFull(c, user); err != nil {
		return false
	}
	var plen [1]byte
	if _, err := io.ReadFull(c, plen[:]); err != nil {
		return false
	}
	pass := make([]byte, plen[0])
	if _, err := io.ReadFull(c, pass); err != nil {
		return false
	}
	userOK := subtle.ConstantTimeCompare(user, []byte(r.socksUser))
	passOK := subtle.ConstantTimeCompare(pass, []byte(r.socksPass))
	if userOK&passOK != 1 {
		_, _ = c.Write([]byte{0x01, 0x01})
		return false
	}
	_, err := c.Write([]byte{0x01, 0x00})
	return err == nil
}

// handleSocksConn handles a single SOCKS5 TCP client connection.
func (r *AmneziaWgRunner) handleSocksConn(ctx context.Context, c net.Conn) {
	defer c.Close()

	// 1. Negotiation. A client that goes quiet here would otherwise hold this goroutine until
	// the runner stops.
	_ = c.SetDeadline(time.Now().Add(socksHandshakeTimeout))
	var header [2]byte
	if _, err := io.ReadFull(c, header[:]); err != nil || header[0] != 0x05 {
		return
	}
	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if !r.socksAuthenticate(c, methods) {
		return
	}

	// 2. Request
	var reqHeader [4]byte
	if _, err := io.ReadFull(c, reqHeader[:]); err != nil {
		return
	}
	if reqHeader[0] != 0x05 {
		return
	}

	destAddr, destPort, err := amneziawg.ReadAddress(c, reqHeader[3])
	if err != nil {
		_ = amneziawg.SendReply(c, 0x08) // Address type not supported
		return
	}
	// The request is complete: the dial has its own timeout and the stream may idle.
	_ = c.SetDeadline(time.Time{})
	if reqHeader[1] == 0x03 { // UDP ASSOCIATE
		var requested *net.UDPAddr
		if ip := net.ParseIP(destAddr); ip != nil && destPort != 0 {
			requested = &net.UDPAddr{IP: ip, Port: int(destPort)}
		}
		r.handleSocksUDPAssociate(ctx, c, requested)
		return
	}
	if reqHeader[1] != 0x01 { // CONNECT
		_ = amneziawg.SendReply(c, 0x07) // Command not supported
		return
	}

	// 3. Dial target via AmneziaWG netstack
	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	defer dialCancel()

	var tcpAddr *net.TCPAddr
	if ip := net.ParseIP(destAddr); ip != nil {
		tcpAddr = &net.TCPAddr{IP: ip, Port: int(destPort)}
	} else {
		ip, err := r.lookupTunnelHost(dialCtx, destAddr)
		if err != nil {
			_ = amneziawg.SendReply(c, 0x04) // Host unreachable
			return
		}
		tcpAddr = &net.TCPAddr{IP: ip, Port: int(destPort)}
	}

	remoteConn, err := r.tnet.DialContextTCP(dialCtx, tcpAddr)
	if err != nil {
		_ = amneziawg.SendReply(c, 0x05) // Connection refused
		return
	}
	defer remoteConn.Close()

	// 4. Send SOCKS Success response
	if err := amneziawg.SendReply(c, 0x00); err != nil {
		return
	}

	// 5. Bidirectional stream copy with half-close
	amneziawg.Relay(ctx, c, remoteConn)
}

// handleSocksUDPAssociate implements SOCKS5 UDP ASSOCIATE. Xray uses this
// path for UDP traffic (including ordinary DNS), so accepting CONNECT alone
// would make an AmneziaWG bridge only partially functional.
//
// requested is the source the client named in its request (RFC 1928), when it named one: then
// only datagrams from exactly that address and port are relayed.
func (r *AmneziaWgRunner) handleSocksUDPAssociate(ctx context.Context, control net.Conn, requested *net.UDPAddr) {
	clientUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		_ = amneziawg.SendReply(control, 0x01)
		return
	}
	defer clientUDP.Close()

	if err := amneziawg.SendReplyWithAddress(control, 0x00, clientUDP.LocalAddr().(*net.UDPAddr)); err != nil {
		return
	}

	var (
		clientMu      sync.RWMutex
		clientAddr    *net.UDPAddr
		tunnelMu      sync.Mutex
		tunnelUDPs    = make(map[string]net.PacketConn)
		tunnelsClosed bool
		finishOnce    sync.Once
	)
	finished := make(chan struct{})
	finish := func() { finishOnce.Do(func() { close(finished) }) }
	defer func() {
		tunnelMu.Lock()
		defer tunnelMu.Unlock()
		tunnelsClosed = true
		for _, tunnelUDP := range tunnelUDPs {
			_ = tunnelUDP.Close()
		}
	}()

	// RFC 1928 binds the association to the TCP client. On Android both are
	// loopback sockets; accepting packets from a different source would expose
	// the tunnel to unrelated local processes.
	var controlIP net.IP
	if addr, ok := control.RemoteAddr().(*net.TCPAddr); ok {
		controlIP = addr.IP
	}

	go func() {
		_, _ = io.Copy(io.Discard, control)
		finish()
	}()
	go func() {
		// ctx lives as long as the runner; without the finished case this goroutine would
		// outlive every association it belongs to.
		select {
		case <-ctx.Done():
			finish()
		case <-finished:
		}
	}()

	startTunnelResponseLoop := func(tunnelUDP net.PacketConn) {
		go func() {
			bufferRef := amneziawg.UDPBuffers.Get().(*[]byte)
			defer amneziawg.UDPBuffers.Put(bufferRef)
			buffer := *bufferRef
			for {
				n, source, err := tunnelUDP.ReadFrom(buffer)
				if err != nil {
					finish()
					return
				}
				remote, ok := source.(*net.UDPAddr)
				if !ok {
					continue
				}
				packet := amneziawg.BuildUDPDatagram(remote, buffer[:n])

				clientMu.RLock()
				destination := clientAddr
				clientMu.RUnlock()
				if destination != nil {
					_, _ = clientUDP.WriteToUDP(packet, destination)
				}
			}
		}()
	}

	tunnelFor := func(destination *net.UDPAddr) (net.PacketConn, error) {
		bindAddress, family, err := amneziawg.UDPBindAddress(destination, r.localAddrs)
		if err != nil {
			return nil, err
		}

		tunnelMu.Lock()
		defer tunnelMu.Unlock()
		if tunnelsClosed {
			return nil, net.ErrClosed
		}
		if tunnelUDP := tunnelUDPs[family]; tunnelUDP != nil {
			return tunnelUDP, nil
		}

		tunnelUDP, err := r.tnet.ListenUDP(bindAddress)
		if err != nil {
			return nil, err
		}
		tunnelUDPs[family] = tunnelUDP
		startTunnelResponseLoop(tunnelUDP)
		return tunnelUDP, nil
	}

	go func() {
		bufferRef := amneziawg.UDPBuffers.Get().(*[]byte)
		defer amneziawg.UDPBuffers.Put(bufferRef)
		buffer := *bufferRef
		for {
			n, source, err := clientUDP.ReadFromUDP(buffer)
			if err != nil {
				finish()
				return
			}
			if !r.udpSourceAllowed(source, controlIP, requested) {
				continue
			}
			payload, destination, err := r.parseSocksUDPDatagram(ctx, buffer[:n])
			if err != nil {
				continue
			}
			tunnelUDP, err := tunnelFor(destination)
			if err != nil {
				continue
			}

			clientMu.Lock()
			if clientAddr == nil {
				clientAddr = &net.UDPAddr{IP: append(net.IP(nil), source.IP...), Port: source.Port}
			}
			allowedSource := clientAddr.IP.Equal(source.IP) && clientAddr.Port == source.Port
			clientMu.Unlock()
			if !allowedSource {
				continue
			}

			if _, err := tunnelUDP.WriteTo(payload, destination); err != nil {
				continue
			}
		}
	}()

	<-finished
}

// udpSourceAllowed reports whether a datagram from source belongs to the association: from the
// exact address the client named, or, when it named none (an unspecified address or port 0),
// from the IP of its control connection.
func (r *AmneziaWgRunner) udpSourceAllowed(source *net.UDPAddr, controlIP net.IP, requested *net.UDPAddr) bool {
	if requested != nil {
		ip := requested.IP
		if ip.IsUnspecified() {
			ip = controlIP
		}
		return source.Port == requested.Port && (ip == nil || source.IP.Equal(ip))
	}
	return controlIP == nil || source.IP.Equal(controlIP)
}

func (r *AmneziaWgRunner) parseSocksUDPDatagram(ctx context.Context, packet []byte) ([]byte, *net.UDPAddr, error) {
	// RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT | DATA
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return nil, nil, errors.New("invalid or fragmented SOCKS UDP datagram")
	}
	reader := bytes.NewReader(packet[3:])
	host, port, err := amneziawg.ReadAddress(reader, packet[3])
	if err != nil {
		return nil, nil, err
	}
	consumed := len(packet[3:]) - reader.Len()
	if consumed <= 0 || 3+consumed > len(packet) {
		return nil, nil, errors.New("invalid SOCKS UDP destination")
	}
	destination, err := r.resolveTunnelUDPAddress(ctx, host, port)
	if err != nil {
		return nil, nil, err
	}
	return packet[3+consumed:], destination, nil
}

func (r *AmneziaWgRunner) resolveTunnelUDPAddress(ctx context.Context, host string, port uint16) (*net.UDPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: int(port)}, nil
	}
	ip, err := r.lookupTunnelHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q through AmneziaWG: %w", host, err)
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}
