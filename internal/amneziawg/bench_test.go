// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package amneziawg

import (
	"context"
	"io"
	"net"
	"testing"
)

func benchTCPPair(b *testing.B) (client, server net.Conn) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); accepted <- c }()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	return client, <-accepted
}

// BenchmarkRelay pushes bulk data through Relay, the path every AmneziaWG SOCKS connection takes.
func BenchmarkRelay(b *testing.B) {
	srcClient, srcSide := benchTCPPair(b)
	dstSide, dstServer := benchTCPPair(b)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Relay(ctx, srcSide, dstSide); close(done) }()
	defer func() { cancel(); <-done; srcClient.Close(); dstServer.Close() }()

	chunk := make([]byte, 64<<10)
	b.SetBytes(int64(len(chunk)))
	go func() {
		for i := 0; i < b.N; i++ {
			if _, err := srcClient.Write(chunk); err != nil {
				return
			}
		}
	}()
	b.ResetTimer()
	if _, err := io.CopyN(io.Discard, dstServer, int64(b.N)*int64(len(chunk))); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkBaselineCopy is the same transfer through a plain io.Copy, for comparison.
func BenchmarkBaselineCopy(b *testing.B) {
	srcClient, srcSide := benchTCPPair(b)
	dstSide, dstServer := benchTCPPair(b)
	go func() { _, _ = io.Copy(dstSide, srcSide) }()
	defer func() { srcClient.Close(); srcSide.Close(); dstSide.Close(); dstServer.Close() }()

	chunk := make([]byte, 64<<10)
	b.SetBytes(int64(len(chunk)))
	go func() {
		for i := 0; i < b.N; i++ {
			if _, err := srcClient.Write(chunk); err != nil {
				return
			}
		}
	}()
	b.ResetTimer()
	if _, err := io.CopyN(io.Discard, dstServer, int64(b.N)*int64(len(chunk))); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkBuildUDPDatagram(b *testing.B) {
	src := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443}
	payload := make([]byte, 1200)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		_ = BuildUDPDatagram(src, payload)
	}
}
