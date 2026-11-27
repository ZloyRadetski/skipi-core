// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import (
	"github.com/ZloyRadetski/skipi-core/desktop/egress"
	"github.com/ZloyRadetski/skipi-core/desktop/multilink"
	"github.com/ZloyRadetski/skipi-core/internal/hostlinks"
)

var (
	hostLinks = &hostlinks.Source{}
	// hostMerging is link merging for a host that owns the networks (Android): the application reports the links.
	hostMerging = multilink.NewEngine(multilink.EngineConfig{
		Discover: hostLinks.Discover,
		Kinds:    hostLinks.Kinds,
		Attach:   egress.System().SetScheduler,
	})
)

func init() { hostlinks.InstallBinder() }

// MultilinkSetLinks reports the network links the application sees, as a JSON array of
// {"id","name","kind","ipv4","ipv6","handle","phone"}. Call it whenever a link comes, goes or changes; link
// merging follows. A list that does not parse changes nothing.
func MultilinkSetLinks(linksJSON string) error {
	if err := hostLinks.SetJSON(linksJSON); err != nil {
		return err
	}
	hostMerging.Rescan()
	return nil
}

// MultilinkApply applies the link merging settings (JSON, see multilink.Settings): it switches merging on or off
// and changes the rest while it runs, without touching open connections. A refused setting changes nothing.
func MultilinkApply(settingsJSON string) error { return hostMerging.ApplyJSON(settingsJSON) }

// MultilinkStatus returns the links and what merging does with them as JSON (see multilink.Status).
func MultilinkStatus() string { return hostMerging.StatusJSON() }
