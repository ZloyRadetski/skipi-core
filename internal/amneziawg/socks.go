// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package amneziawg

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	// halfCloseTimeout is how long the other direction may keep going once one has ended.
	halfCloseTimeout = 30 * time.Second

	copyBufferSize = 32 * 1024
	udpBufferSize  = 64 * 1024
)

var (
	copyBuffers = sync.Pool{New: func() any { b := make([]byte, copyBufferSize); return &b }}
	// UDPBuffers pools the datagram buffers of UDP ASSOCIATE sessions (*[]byte values).
	UDPBuffers = sync.Pool{New: func() any { b := make([]byte, udpBufferSize); return &b }}
)

// smallCopyBufferSize is what a relay direction holds while it waits or carries little traffic.
const smallCopyBufferSize = 2 * 1024

// Seams for the large pooled copy buffer, so tests can count them.
var (
	takeCopyBuffer   = func() *[]byte { return copyBuffers.Get().(*[]byte) }
	returnCopyBuffer = func(b *[]byte) { copyBuffers.Put(b) }
)

// copyPooled copies src to dst. Most relayed connections sit idle most of the time, and a 32 KiB
// buffer per direction made every one of them cost 64 KiB. A direction now reads into a small
// buffer and takes a large pooled one only while reads fill the small one (bulk traffic), and
// hands it back as soon as a read comes in under the small size. Calls go straight to Read and
// Write, so the buffer used is really this one.
func copyPooled(dst io.Writer, src io.Reader) error {
	small := make([]byte, smallCopyBufferSize)
	buf := small
	var large *[]byte
	defer func() {
		if large != nil {
			returnCopyBuffer(large)
		}
	}()
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			w, werr := dst.Write(buf[:n])
			if werr != nil {
				return werr
			}
			if w != n {
				return io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return nil
			}
			return rerr
		}
		switch {
		case large == nil && n == len(small):
			large = takeCopyBuffer()
			buf = *large
		case large != nil && n < len(small):
			returnCopyBuffer(large)
			large = nil
			buf = small
		}
	}
}

type closeWriter interface{ CloseWrite() error }

// Relay moves bytes both ways until both directions end. When one direction finishes cleanly its
// write side is shut down so the peer sees EOF and may still finish its answer; a failed copy, a
// cancelled ctx or the grace period after the first direction ends closes both connections.
func Relay(ctx context.Context, a, b net.Conn) {
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
				timer := time.NewTimer(halfCloseTimeout)
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

// ReadAddress reads an RFC 1928 address from a TCP SOCKS request.
func ReadAddress(r io.Reader, atyp byte) (string, uint16, error) {
	var host string
	switch atyp {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(ip[:]).String()
	case 0x03: // Domain name
		var lenByte [1]byte
		if _, err := io.ReadFull(r, lenByte[:]); err != nil {
			return "", 0, err
		}
		if lenByte[0] == 0 {
			return "", 0, errors.New("empty SOCKS domain")
		}
		domainBytes := make([]byte, int(lenByte[0]))
		if _, err := io.ReadFull(r, domainBytes); err != nil {
			return "", 0, err
		}
		host = string(domainBytes)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(ip[:]).String()
	default:
		return "", 0, fmt.Errorf("unsupported SOCKS address type %d", atyp)
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(r, portBytes[:]); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(portBytes[:]), nil
}

// SendReply writes a SOCKS5 reply with an all-zero bound address.
func SendReply(c net.Conn, rep byte) error {
	return SendReplyWithAddress(c, rep, &net.UDPAddr{IP: net.IPv4zero, Port: 0})
}

// SendReplyWithAddress writes a SOCKS5 reply carrying the bound address.
func SendReplyWithAddress(c net.Conn, rep byte, addr *net.UDPAddr) error {
	if addr == nil {
		addr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	ip := addr.IP
	reply := []byte{0x05, rep, 0x00}
	if ip4 := ip.To4(); ip4 != nil {
		reply = append(reply, 0x01)
		reply = append(reply, ip4...)
	} else if ip16 := ip.To16(); ip16 != nil {
		reply = append(reply, 0x04)
		reply = append(reply, ip16...)
	} else {
		reply = append(reply, 0x01, 0, 0, 0, 0)
	}
	reply = binary.BigEndian.AppendUint16(reply, uint16(addr.Port))
	_, err := c.Write(reply)
	return err
}

// UDPBindAddress selects the configured local address matching the
// destination family before creating a netstack UDP endpoint. Passing nil to
// amneziawg-go's ListenUDP leaves gVisor with protocol number 0, which panics
// the whole Android process on the first UDP ASSOCIATE packet. An IPv6 wildcard
// is also not accepted by this netstack, so use the explicit tunnel address.
func UDPBindAddress(destination *net.UDPAddr, localAddrs []netip.Addr) (*net.UDPAddr, string, error) {
	if destination == nil || len(destination.IP) == 0 {
		return nil, "", errors.New("missing UDP destination")
	}

	isIPv4 := destination.IP.To4() != nil
	if !isIPv4 && destination.IP.To16() == nil {
		return nil, "", errors.New("invalid UDP destination IP")
	}

	family := "ipv6"
	if isIPv4 {
		family = "ipv4"
	}
	for _, localAddr := range localAddrs {
		localAddr = localAddr.Unmap()
		if !localAddr.IsValid() || localAddr.IsUnspecified() || localAddr.Is4() != isIPv4 {
			continue
		}
		return &net.UDPAddr{IP: append(net.IP(nil), localAddr.AsSlice()...), Port: 0}, family, nil
	}
	return nil, "", fmt.Errorf("no local AmneziaWG %s address configured for UDP", family)
}

// BuildUDPDatagram wraps payload in a SOCKS5 UDP datagram header addressed from source.
func BuildUDPDatagram(source *net.UDPAddr, payload []byte) []byte {
	packet := make([]byte, 0, 3+1+len(source.IP)+2+len(payload))
	packet = append(packet, 0, 0, 0) // RSV and FRAG
	if ip4 := source.IP.To4(); ip4 != nil {
		packet = append(packet, 0x01)
		packet = append(packet, ip4...)
	} else {
		packet = append(packet, 0x04)
		packet = append(packet, source.IP.To16()...)
	}
	packet = binary.BigEndian.AppendUint16(packet, uint16(source.Port))
	return append(packet, payload...)
}
