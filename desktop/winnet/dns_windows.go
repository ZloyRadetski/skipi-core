// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package winnet

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procConvertInterfaceLuidToGuid = iphlpapi.NewProc("ConvertInterfaceLuidToGuid")
	procSetInterfaceDnsSettings    = iphlpapi.NewProc("SetInterfaceDnsSettings")
	procGetIpInterfaceEntry        = iphlpapi.NewProc("GetIpInterfaceEntry")
	procSetIpInterfaceEntry        = iphlpapi.NewProc("SetIpInterfaceEntry")
	procDnsFlushResolverCache      = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")
)

const (
	dnsInterfaceSettingsVersion1 = 1
	dnsSettingIPv6               = 0x0001
	dnsSettingNameServer         = 0x0002

	dnsSettingsSize = 64 // sizeof(DNS_INTERFACE_SETTINGS) on a 64-bit Windows
)

// dnsSettings is DNS_INTERFACE_SETTINGS (version 1), laid out as iphlpapi.h does on a 64-bit Windows, with only
// the name servers set.
type dnsSettings struct {
	Version           uint32
	_                 uint32
	Flags             uint64
	Domain            *uint16
	NameServer        *uint16
	SearchList        *uint16
	RegistrationOn    uint32
	RegisterAdapter   uint32
	EnableLLMNR       uint32
	QueryAdapterName  uint32
	ProfileNameServer *uint16
}

// nativeSetDNS gives the adapter its DNS servers and the lowest interface metric (what the DNS client ranks
// adapters by). IPv4 and IPv6 servers are separate settings. A system without SetInterfaceDnsSettings (before
// Windows 10 2004) reports an error, and the PowerShell script takes over.
func nativeSetDNS(adapter string, servers []netip.Addr) error {
	luid, err := interfaceLuid(adapter)
	if err != nil {
		return err
	}
	var guid windows.GUID
	if r, _, _ := procConvertInterfaceLuidToGuid.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&guid))); r != 0 {
		return fmt.Errorf("ConvertInterfaceLuidToGuid: %w", windows.Errno(r))
	}
	for _, family := range []struct {
		v6   bool
		flag uint64
	}{{false, dnsSettingNameServer}, {true, dnsSettingNameServer | dnsSettingIPv6}} {
		var list []string
		for _, s := range servers {
			if s.Is6() == family.v6 {
				list = append(list, s.String())
			}
		}
		if len(list) == 0 {
			continue
		}
		names, err := windows.UTF16PtrFromString(strings.Join(list, ","))
		if err != nil {
			return err
		}
		settings := dnsSettings{Version: dnsInterfaceSettingsVersion1, Flags: family.flag, NameServer: names}
		if r, _, _ := procSetInterfaceDnsSettings.Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&settings))); r != 0 {
			return fmt.Errorf("SetInterfaceDnsSettings: %w", windows.Errno(r))
		}
	}
	return setInterfaceMetric(luid, routeMetric)
}

// MIB_IPINTERFACE_ROW is 168 bytes on a 64-bit Windows. It is read from the system, changed in three places
// and written back, so only these offsets matter.
const (
	ipInterfaceRowSize       = 168
	ipInterfaceUseAutoMetric = 44
	ipInterfaceSitePrefixLen = 144
	ipInterfaceMetric        = 148
	errorNotFoundFamily      = 1168 // ERROR_NOT_FOUND: the adapter has no such protocol
)

// readIPInterface fills the row of an adapter for a family (afINET or afINET6) from the system.
func readIPInterface(luid uint64, family uint16) ([]byte, error) {
	row := make([]byte, ipInterfaceRowSize)
	binary.LittleEndian.PutUint16(row[0:], family)
	binary.LittleEndian.PutUint64(row[8:], luid)
	if r, _, _ := procGetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row[0]))); r != 0 {
		return nil, windows.Errno(r)
	}
	return row, nil
}

// setInterfaceMetric pins the interface metric of both protocols; a protocol the adapter does not have is skipped.
func setInterfaceMetric(luid uint64, metric uint32) error {
	for _, family := range []uint16{afINET, afINET6} {
		row, err := readIPInterface(luid, family)
		if err != nil {
			if errno, ok := err.(windows.Errno); ok && errno == errorNotFoundFamily && family == afINET6 {
				continue
			}
			return fmt.Errorf("GetIpInterfaceEntry: %w", err)
		}
		row[ipInterfaceUseAutoMetric] = 0
		binary.LittleEndian.PutUint32(row[ipInterfaceMetric:], metric)
		if family == afINET {
			// Documented quirk: SetIpInterfaceEntry for IPv4 fails unless the site prefix length is cleared.
			binary.LittleEndian.PutUint32(row[ipInterfaceSitePrefixLen:], 0)
		}
		if r, _, _ := procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row[0]))); r != 0 {
			return fmt.Errorf("SetIpInterfaceEntry: %w", windows.Errno(r))
		}
	}
	return nil
}

// nativeFlushDNS drops the resolver cache.
func nativeFlushDNS() error {
	if r, _, err := procDnsFlushResolverCache.Call(); r == 0 {
		return fmt.Errorf("DnsFlushResolverCache: %v", err)
	}
	return nil
}
