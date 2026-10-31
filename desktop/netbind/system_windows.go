// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package netbind

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ipUnicastIf   = 31 // IP_UNICAST_IF / IPV6_UNICAST_IF
	ipprotoIP     = 0
	ipprotoIPv6   = 41
	adapterFlags  = windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	maxAdapterTry = 3
)

// NewSystemBinder returns a Binder driven by the adapters Windows reports. exclude is the tunnel's
// own adapter name, which is never chosen. The interface is identified by its index in decimal.
func NewSystemBinder(exclude string) *Binder {
	return &Binder{
		Lookup: func() (string, bool) {
			adapters, err := systemAdapters()
			if err != nil {
				return "", false
			}
			index, ok := DefaultAdapter(adapters, exclude)
			if !ok {
				return "", false
			}
			return strconv.FormatUint(uint64(index), 10), true
		},
		Bind: bindToInterfaceIndex,
		TTL:  time.Second,
		Now:  time.Now,
		// stderr reaches the application's log, independent of the Xray log level.
		OnChoose: func(iface string, ok bool) {
			if ok {
				log.Printf("SKIPI TUN: binding Core sockets to interface %s", iface)
			} else {
				log.Printf("SKIPI TUN: no physical default route; Core sockets follow the system routes")
			}
		},
		OnBindError: func(iface string, err error) {
			log.Printf("SKIPI TUN: IP_UNICAST_IF %s failed: %v", iface, err)
		},
	}
}

// bindToInterfaceIndex pins a socket to an interface. A socket is IPv4 or IPv6, so exactly one of
// the two options applies; the bind succeeds when either one is accepted.
func bindToInterfaceIndex(fd uintptr, iface string) error {
	index, err := strconv.ParseUint(iface, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid interface index %q: %w", iface, err)
	}
	handle := windows.Handle(fd)
	v4 := windows.SetsockoptInt(handle, ipprotoIP, ipUnicastIf, int(UnicastIfValueV4(uint32(index))))
	if v4 == nil {
		return nil
	}
	v6 := windows.SetsockoptInt(handle, ipprotoIPv6, ipUnicastIf, int(index))
	if v6 == nil {
		return nil
	}
	return errors.Join(v4, v6)
}

func systemAdapters() ([]Adapter, error) {
	size := uint32(15 * 1024)
	var buffer []byte
	for attempt := 0; attempt < maxAdapterTry; attempt++ {
		buffer = make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, adapterFlags, 0, first, &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) || attempt == maxAdapterTry-1 {
			return nil, err
		}
	}
	var adapters []Adapter
	for current := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])); current != nil; current = current.Next {
		adapters = append(adapters, Adapter{
			Index:      current.IfIndex,
			Name:       windows.UTF16PtrToString(current.FriendlyName),
			Up:         current.OperStatus == windows.IfOperStatusUp,
			HasGateway: hasIPv4Gateway(current),
			Loopback:   current.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK,
			Metric:     current.Ipv4Metric,
		})
	}
	return adapters, nil
}

func hasIPv4Gateway(adapter *windows.IpAdapterAddresses) bool {
	for gateway := adapter.FirstGatewayAddress; gateway != nil; gateway = gateway.Next {
		if gateway.Address.Sockaddr != nil && gateway.Address.Sockaddr.Addr.Family == windows.AF_INET {
			return true
		}
	}
	return false
}
