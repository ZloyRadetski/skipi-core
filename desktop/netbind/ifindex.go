// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package netbind

import (
	"sync"
	"time"
)

// ifIndexCache remembers interface name to index answers: resolving a name enumerates the
// system's interfaces, which a dial must not do for every socket.
type ifIndexCache struct {
	resolve func(name string) (int, error)
	ttl     time.Duration
	now     func() time.Time

	mu      sync.Mutex
	entries map[string]ifIndexEntry
}

type ifIndexEntry struct {
	index   int
	expires time.Time
}

func newIfIndexCache(resolve func(string) (int, error), ttl time.Duration, now func() time.Time) *ifIndexCache {
	return &ifIndexCache{resolve: resolve, ttl: ttl, now: now, entries: make(map[string]ifIndexEntry)}
}

func (c *ifIndexCache) index(name string) (int, error) {
	now := c.now()
	c.mu.Lock()
	if e, ok := c.entries[name]; ok && now.Before(e.expires) {
		c.mu.Unlock()
		return e.index, nil
	}
	c.mu.Unlock()
	index, err := c.resolve(name)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	c.entries[name] = ifIndexEntry{index: index, expires: now.Add(c.ttl)}
	c.mu.Unlock()
	return index, nil
}
