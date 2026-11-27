// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package hostlinks is link merging's view of the network links when the host application, not Core, knows them:
// on Android the system keeps Wi-Fi, mobile data and the rest as networks that only the application may list, and
// each socket is bound to one through the system. The application reports the links as JSON whenever they change.
package hostlinks

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"github.com/ZloyRadetski/skipi-core/desktop/multilink/nics"
)

// Link is one network the host reports.
type Link struct {
	// ID stays the same across reconnects of the same kind of link (the application chooses it).
	ID   string `json:"id"`
	Name string `json:"name"`
	// Kind is "wifi", "ethernet", "phone", "mobile" or anything else for a generic link.
	Kind string `json:"kind"`
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
	// Handle is the system's handle of the network; it changes when the network reconnects.
	Handle uint64 `json:"handle"`
	// Phone asks the scheduler to go easy on the link (a metered mobile connection).
	Phone bool `json:"phone,omitempty"`
}

// Source holds the last links the host reported.
type Source struct {
	mu    sync.Mutex
	links []Link
}

// SetJSON replaces the links; a list that does not parse changes nothing.
func (s *Source) SetJSON(data string) error {
	var links []Link
	if err := json.Unmarshal([]byte(data), &links); err != nil {
		return fmt.Errorf("invalid links: %w", err)
	}
	seen := map[string]bool{}
	for _, l := range links {
		if l.ID == "" || l.Handle == 0 {
			return fmt.Errorf("link %q needs an id and a handle", l.Name)
		}
		if seen[l.ID] {
			return fmt.Errorf("link id %q is listed twice", l.ID)
		}
		seen[l.ID] = true
	}
	s.mu.Lock()
	s.links = links
	s.mu.Unlock()
	return nil
}

// Discover lists the links as adapters. Nothing is skipped: the host decides what is a link.
func (s *Source) Discover() ([]nics.Nic, []nics.Skip, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]nics.Nic, 0, len(s.links))
	for _, l := range s.links {
		nic := nics.Nic{ID: l.ID, Name: l.Name, Handle: l.Handle, Weight: 1, Phone: l.Phone || l.Kind == "phone" || l.Kind == "mobile"}
		if ip := net.ParseIP(l.IPv4); ip != nil && ip.To4() != nil {
			nic.IP = ip.To4()
		}
		if ip := net.ParseIP(l.IPv6); ip != nil && ip.To4() == nil {
			nic.IP6 = ip
		}
		if nic.IP == nil && nic.IP6 == nil {
			continue
		}
		out = append(out, nic)
	}
	return out, nil, nil
}

// Kinds names each link's kind by its name, as the engine asks.
func (s *Source) Kinds() map[string]nics.Kind {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]nics.Kind, len(s.links))
	for _, l := range s.links {
		switch l.Kind {
		case "wifi":
			out[l.Name] = nics.WiFi
		case "ethernet":
			out[l.Name] = nics.Ethernet
		case "phone":
			out[l.Name] = nics.Phone
		case "mobile":
			out[l.Name] = nics.Mobile
		default:
			out[l.Name] = nics.Unknown
		}
	}
	return out
}
