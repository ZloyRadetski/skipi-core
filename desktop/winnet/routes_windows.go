// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build windows

package winnet

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                        = windows.NewLazySystemDLL("iphlpapi.dll")
	procConvertInterfaceAliasToLuid = iphlpapi.NewProc("ConvertInterfaceAliasToLuid")
	procCreateIpForwardEntry2       = iphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2       = iphlpapi.NewProc("DeleteIpForwardEntry2")
)

const (
	errorNotFound           = 1168 // ERROR_NOT_FOUND
	errorObjectAlreadyExist = 5010 // ERROR_OBJECT_ALREADY_EXISTS
)

func interfaceLuid(name string) (uint64, error) {
	alias, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var luid uint64
	if r, _, _ := procConvertInterfaceAliasToLuid.Call(uintptr(unsafe.Pointer(alias)), uintptr(unsafe.Pointer(&luid))); r != 0 {
		return 0, fmt.Errorf("adapter %s has no LUID: %w", name, windows.Errno(r))
	}
	return luid, nil
}

// nativeAddRoute installs an on-link route into the adapter. It lives only for this session, like the
// store=active of netsh. A route that already exists is not an error.
func nativeAddRoute(adapter string, prefix netip.Prefix) error {
	luid, err := interfaceLuid(adapter)
	if err != nil {
		return err
	}
	row, err := encodeRouteRow(luid, prefix, routeMetric)
	if err != nil {
		return err
	}
	switch r, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row[0]))); r {
	case 0, errorObjectAlreadyExist:
		return nil
	default:
		return fmt.Errorf("CreateIpForwardEntry2 %s: %w", prefix, windows.Errno(r))
	}
}

// nativeDeleteRoute removes the route; one that is already gone is not an error.
func nativeDeleteRoute(adapter string, prefix netip.Prefix) error {
	luid, err := interfaceLuid(adapter)
	if err != nil {
		return err
	}
	row, err := encodeRouteRow(luid, prefix, routeMetric)
	if err != nil {
		return err
	}
	switch r, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row[0]))); r {
	case 0, errorNotFound:
		return nil
	default:
		return fmt.Errorf("DeleteIpForwardEntry2 %s: %w", prefix, windows.Errno(r))
	}
}
