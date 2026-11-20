// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// C5: the AmneziaWG SOCKS listener is the exit of the tunnel for anything on the device that can
// reach loopback. With credentials it asks for them (RFC 1929), it holds a bounded number of
// connections, and a UDP association answers only the client that asked for it.

const awgRunnerJSON = `{"secretKey":"aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=","address":["10.8.0.2/32"],"dnsServers":["1.1.1.1"],
	"peers":[{"publicKey":"YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=","endpoint":"127.0.0.1:59999","allowedIPs":["0.0.0.0/0"]}]%s}`

func startTestRunner(t *testing.T, extra string) *AmneziaWgRunner {
	t.Helper()
	settings, err := ParseAmneziaWgSettings(fmt.Sprintf(awgRunnerJSON, extra))
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewAmneziaWgRunner(settings, 0)
	if err != nil {
		t.Fatal(err)
	}
	runner.socksPort = 0
	if err := runner.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runner.Stop() })
	return runner
}

func dialRunner(t *testing.T, r *AmneziaWgRunner) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", r.socksPort))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func authenticate(t *testing.T, c net.Conn, user, pass string) byte {
	t.Helper()
	_, _ = c.Write([]byte{5, 1, 2})
	var greeting [2]byte
	if _, err := io.ReadFull(c, greeting[:]); err != nil || greeting != [2]byte{5, 2} {
		t.Fatalf("greeting = %v, %v; want username/password", greeting, err)
	}
	msg := []byte{1, byte(len(user))}
	msg = append(msg, user...)
	msg = append(msg, byte(len(pass)))
	msg = append(msg, pass...)
	_, _ = c.Write(msg)
	var status [2]byte
	if _, err := io.ReadFull(c, status[:]); err != nil {
		return 0xff
	}
	return status[1]
}

func TestAwgSocksWithCredentialsRefusesAClientWithoutThem(t *testing.T) {
	r := startTestRunner(t, `,"socksUser":"skipi","socksPass":"s3cret"`)
	c := dialRunner(t, r)
	_, _ = c.Write([]byte{5, 1, 0})
	var greeting [2]byte
	if _, err := io.ReadFull(c, greeting[:]); err != nil || greeting != [2]byte{5, 0xff} {
		t.Fatalf("greeting = %v, %v; want no acceptable method", greeting, err)
	}
}

func TestAwgSocksWithCredentialsChecksThem(t *testing.T) {
	r := startTestRunner(t, `,"socksUser":"skipi","socksPass":"s3cret"`)
	if status := authenticate(t, dialRunner(t, r), "skipi", "wrong"); status == 0 {
		t.Fatal("a wrong password was accepted")
	}
	if status := authenticate(t, dialRunner(t, r), "other", "s3cret"); status == 0 {
		t.Fatal("a wrong user was accepted")
	}
	if status := authenticate(t, dialRunner(t, r), "skipi", "s3cret"); status != 0 {
		t.Fatalf("the right credentials were refused: %d", status)
	}
}

func TestAwgSocksHoldsABoundedNumberOfConnections(t *testing.T) {
	defer func(old int) { maxSocksConns = old }(maxSocksConns)
	maxSocksConns = 2
	r := startTestRunner(t, "")
	held := []net.Conn{dialRunner(t, r), dialRunner(t, r)}
	time.Sleep(100 * time.Millisecond) // both are accepted and waiting for their greeting
	extra := dialRunner(t, r)
	var b [1]byte
	if _, err := extra.Read(b[:]); err == nil {
		t.Fatal("a connection over the limit must be closed")
	}
	_ = held[0].Close()
	time.Sleep(100 * time.Millisecond)
	again := dialRunner(t, r)
	_, _ = again.Write([]byte{5, 1, 0})
	var greeting [2]byte
	if _, err := io.ReadFull(again, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatalf("a freed slot must serve again: %v, %v", greeting, err)
	}
}

// A client that names its UDP source in the request gets answers for that source only; another
// local process sending first from the same IP is ignored.
func TestAwgUDPAssociationAcceptsOnlyTheSourceTheClientNamed(t *testing.T) {
	r := startTestRunner(t, "")
	c := dialRunner(t, r)
	own, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	ownPort := own.LocalAddr().(*net.UDPAddr).Port
	_, _ = c.Write([]byte{5, 1, 0})
	var greeting [2]byte
	_, _ = io.ReadFull(c, greeting[:])
	_, _ = c.Write([]byte{5, 3, 0, 1, 127, 0, 0, 1, byte(ownPort >> 8), byte(ownPort)})
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil || reply[1] != 0 {
		t.Fatalf("associate reply = %v, %v", reply, err)
	}
	if allowed := r.udpSourceAllowed(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ownPort + 1}, net.IPv4(127, 0, 0, 1), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ownPort}); allowed {
		t.Fatal("another port on the same IP must not be served")
	}
	if allowed := r.udpSourceAllowed(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ownPort}, net.IPv4(127, 0, 0, 1), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ownPort}); !allowed {
		t.Fatal("the named source must be served")
	}
}

// A session protects its own runner without the app's help: Core picks credentials and gives
// them to both the runner and the Xray outbound that points at it.
func TestSessionGivesTheAwgBridgeCredentials(t *testing.T) {
	xray := `{"outbounds":[{"tag":"awg","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":10809}]}},
		{"tag":"other","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":2080}]}},
		{"tag":"direct","protocol":"freedom","settings":{"big":12345678901234567890}}]}`
	awg := `{"secretKey":"k","dnsServers":["1.1.1.1"]}`
	gotXray, gotAwg, err := secureAwgBridge(xray, awg, 10809)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		SocksUser string `json:"socksUser"`
		SocksPass string `json:"socksPass"`
	}
	if err := json.Unmarshal([]byte(gotAwg), &cfg); err != nil || len(cfg.SocksUser) < 8 || len(cfg.SocksPass) < 16 {
		t.Fatalf("runner config = %s (%v)", gotAwg, err)
	}
	var x struct {
		Outbounds []struct {
			Tag      string `json:"tag"`
			Settings struct {
				Servers []struct {
					Users []struct {
						User string `json:"user"`
						Pass string `json:"pass"`
					} `json:"users"`
				} `json:"servers"`
			} `json:"settings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(gotXray), &x); err != nil {
		t.Fatal(err)
	}
	users := x.Outbounds[0].Settings.Servers[0].Users
	if len(users) != 1 || users[0].User != cfg.SocksUser || users[0].Pass != cfg.SocksPass {
		t.Fatalf("the bridge outbound must carry the runner's credentials: %s", gotXray)
	}
	if len(x.Outbounds[1].Settings.Servers[0].Users) != 0 {
		t.Fatal("an outbound to another port must stay as it is")
	}
	if !strings.Contains(gotXray, "12345678901234567890") {
		t.Fatalf("numbers must survive the rewrite: %s", gotXray)
	}

	// Credentials the app chose itself are kept, and the Xray config is left alone.
	own := `{"secretKey":"k","socksUser":"u","socksPass":"p"}`
	gotXray, gotAwg, err = secureAwgBridge(xray, own, 10809)
	if err != nil || gotXray != xray || gotAwg != own {
		t.Fatalf("own credentials: %v\n%s\n%s", err, gotXray, gotAwg)
	}
}
