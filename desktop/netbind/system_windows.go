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

// bindToInterfaceIndex pins a socket to an interface. A dual-stack socket needs both options, so
// both are always tried; the bind succeeds when at least one is accepted.
func bindToInterfaceIndex(fd uintptr, iface string) error {
	index, err := strconv.ParseUint(iface, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid interface index %q: %w", iface, err)
	}
	handle := windows.Handle(fd)
	return applyUnicastIf(func(level, value int) error {
		return windows.SetsockoptInt(handle, level, ipUnicastIf, value)
	}, uint32(index))
}

func applyUnicastIf(set func(level, value int) error, index uint32) error {
	v4 := set(ipprotoIP, int(UnicastIfValueV4(index)))
	v6 := set(ipprotoIPv6, int(index))
	if v4 == nil || v6 == nil {
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
	routeMetrics, routeErr := windowsDefaultRouteMetrics()
	var adapters []Adapter
	for current := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])); current != nil; current = current.Next {
		adapters = append(adapters, Adapter{
			Index:      current.IfIndex,
			Name:       windows.UTF16PtrToString(current.FriendlyName),
			Up:         current.OperStatus == windows.IfOperStatusUp,
			HasGateway: hasIPv4Gateway(current),
			Loopback:   current.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK,
			Metric:     effectiveMetric(current.IfIndex, current.Ipv4Metric, routeMetrics, routeErr == nil),
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

var (
	iphlpapi               = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpForwardTable2 = iphlpapi.NewProc("GetIpForwardTable2")
	procFreeMibTable       = iphlpapi.NewProc("FreeMibTable")
)

// windowsDefaultRouteMetrics reads the IPv4 forwarding table and returns each interface's lowest
// default-route metric.
func windowsDefaultRouteMetrics() (map[uint32]uint32, error) {
	var table unsafe.Pointer
	if r, _, _ := procGetIpForwardTable2.Call(uintptr(windows.AF_INET), uintptr(unsafe.Pointer(&table))); r != 0 {
		return nil, windows.Errno(r)
	}
	defer procFreeMibTable.Call(uintptr(table))
	count := int(*(*uint32)(table))
	raw := unsafe.Slice((*byte)(table), forwardTableHeader+count*forwardRowSize)
	return defaultRouteMetrics(append([]byte(nil), raw...)), nil
}

// effectiveMetric is what Windows ranks routes by: the default route's metric plus the interface
// metric. A VPN adapter often has interface metric 1 but a default route metric in the thousands,
// so ranking by the interface metric alone would pick it over the physical link. An adapter without
// a default route in a table that was read ranks last; without the table the interface metric stays.
func effectiveMetric(index, interfaceMetric uint32, routeMetrics map[uint32]uint32, haveTable bool) uint32 {
	if !haveTable {
		return interfaceMetric
	}
	routeMetric, ok := routeMetrics[index]
	if !ok {
		return ^uint32(0)
	}
	return interfaceMetric + routeMetric
}
