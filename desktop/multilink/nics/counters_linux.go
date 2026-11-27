// Based on net-merge (https://github.com/net-merge/net-merge), Copyright (c) 2026 Rohit Mahto, MIT License;
// see third_party/net-merge. Changes for SKIPI Core: Copyright 2026, Radetski, GPL-3.0.

package nics

import (
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// Octets reads the kernel's byte counters for an adapter. They cover every app's traffic, not
// just what net-merge relays: apps like qBittorrent bind to each adapter directly and bypass the
// TUN, but still show up here.
func Octets(idx int) (in, out uint64, ok bool) {
	return octets.read(idx, time.Now(), resolveName)
}

func resolveName(idx int) (string, error) {
	ifc, err := net.InterfaceByIndex(idx)
	if err != nil {
		return "", err
	}
	return ifc.Name, nil
}

// counterPaths is where one adapter's counters are, kept so a tick that reads them every second does not ask the
// kernel for the adapter list (a netlink dump) each time.
type counterPaths struct {
	rx, tx string
	at     time.Time
}

// counterPathsTTL bounds how long an index is trusted to still mean the same adapter name.
const counterPathsTTL = time.Minute

type counterCache struct {
	mu    sync.Mutex
	paths map[int]counterPaths
}

var octets counterCache

func (c *counterCache) read(idx int, now time.Time, resolve func(int) (string, error)) (in, out uint64, ok bool) {
	if idx <= 0 {
		return 0, 0, false
	}
	c.mu.Lock()
	p, cached := c.paths[idx]
	c.mu.Unlock()
	if cached && now.Sub(p.at) < counterPathsTTL {
		if in, out, ok = readPair(p); ok {
			return in, out, true
		}
	}
	// Not known, too old, or unreadable (the adapter went away or was renamed): ask once.
	name, err := resolve(idx)
	if err != nil {
		c.mu.Lock()
		delete(c.paths, idx)
		c.mu.Unlock()
		return 0, 0, false
	}
	stats := "/sys/class/net/" + name + "/statistics/"
	p = counterPaths{rx: stats + "rx_bytes", tx: stats + "tx_bytes", at: now}
	c.mu.Lock()
	if c.paths == nil {
		c.paths = map[int]counterPaths{}
	}
	c.paths[idx] = p
	c.mu.Unlock()
	return readPair(p)
}

func readPair(p counterPaths) (in, out uint64, ok bool) {
	in, err1 := readUint(p.rx)
	out, err2 := readUint(p.tx)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return in, out, true
}

func readUint(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return strconv.ParseUint(string(b), 10, 64)
}
