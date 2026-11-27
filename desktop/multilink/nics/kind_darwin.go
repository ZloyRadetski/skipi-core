// Based on net-merge (https://github.com/net-merge/net-merge), Copyright (c) 2026 Rohit Mahto, MIT License;
// see third_party/net-merge. Changes for SKIPI Core: Copyright 2026, Radetski, GPL-3.0.

package nics

import (
	"net"
	"strings"
)

func AdapterKinds() map[string]Kind {
	ifaces, _ := net.Interfaces()
	out := map[string]Kind{}
	for _, ifc := range ifaces {
		out[ifc.Name] = darwinKind(ifc.Name, portName(ifc.Name))
	}
	return out
}

func darwinKind(name, port string) Kind {
	p := strings.ToLower(port)
	switch {
	case phoneDescription(p) || strings.HasPrefix(name, "feth"):
		return Phone
	case strings.Contains(p, "wi-fi") || strings.Contains(p, "wifi") || strings.Contains(p, "airport"):
		return WiFi
	case strings.Contains(p, "ethernet") || strings.Contains(p, "thunderbolt") || strings.Contains(p, " lan"):
		return Ethernet
	default:
		return Unknown
	}
}
