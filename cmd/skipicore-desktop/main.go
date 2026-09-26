// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build cgo

package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/ZloyRadetski/skipi-core/desktop/bridge"
)

const desktopAPIVersion = "1"

var (
	desktopRuntime = desktopbridge.NewRuntime()
	desktopErrors  struct {
		sync.Mutex
		message string
	}
)

func main() {}

// SkipiCoreDesktopApiVersion returns the C ABI version. The caller owns the
// returned string and must release it with SkipiCoreDesktopFreeString.
//
//export SkipiCoreDesktopApiVersion
func SkipiCoreDesktopApiVersion() *C.char {
	return C.CString(desktopAPIVersion)
}

// SkipiCoreDesktopCoreVersion returns the embedded Xray-core version.
//
//export SkipiCoreDesktopCoreVersion
func SkipiCoreDesktopCoreVersion() *C.char {
	return cString(func() (string, error) {
		return desktopRuntime.CoreVersion(), nil
	})
}

// SkipiCoreDesktopInitializeAssets configures the desktop filesystem resource
// directory. It returns NULL on success, otherwise an owned error string.
//
//export SkipiCoreDesktopInitializeAssets
func SkipiCoreDesktopInitializeAssets(directory *C.char) *C.char {
	return cError(func() error {
		value, err := requiredCString(directory, "asset directory")
		if err != nil {
			return err
		}
		return desktopRuntime.InitializeAssets(value)
	})
}

// SkipiCoreDesktopCreateController allocates an opaque controller handle.
// A zero result means allocation failed; use SkipiCoreDesktopLastError for its
// diagnostic text.
//
//export SkipiCoreDesktopCreateController
func SkipiCoreDesktopCreateController() (result C.uint64_t) {
	defer func() {
		if recovered := recover(); recovered != nil {
			setLastError(panicError(recovered))
			result = 0
		}
	}()
	clearLastError()
	return C.uint64_t(desktopRuntime.CreateController())
}

// SkipiCoreDesktopDestroyController stops an active controller and releases
// its handle. It returns NULL on success, otherwise an owned error string.
//
//export SkipiCoreDesktopDestroyController
func SkipiCoreDesktopDestroyController(handle C.uint64_t) *C.char {
	return cError(func() error {
		return desktopRuntime.DestroyController(desktopbridge.Handle(handle))
	})
}

// SkipiCoreDesktopStart starts a controller from Xray JSON. Desktop local-proxy
// mode uses tunFD = 0. It returns NULL on success, otherwise an owned error string.
//
//export SkipiCoreDesktopStart
func SkipiCoreDesktopStart(handle C.uint64_t, configJSON *C.char, tunFD C.int64_t) *C.char {
	return cError(func() error {
		config, err := requiredCString(configJSON, "Xray configuration")
		if err != nil {
			return err
		}
		return desktopRuntime.Start(desktopbridge.Handle(handle), config, int64(tunFD))
	})
}

// SkipiCoreDesktopStop stops a controller. It returns NULL on success,
// otherwise an owned error string.
//
//export SkipiCoreDesktopStop
func SkipiCoreDesktopStop(handle C.uint64_t) *C.char {
	return cError(func() error {
		return desktopRuntime.Stop(desktopbridge.Handle(handle))
	})
}

// SkipiCoreDesktopIsRunning returns 1 for a running controller, 0 for a
// stopped controller, and -1 on error. Consult SkipiCoreDesktopLastError after
// a -1 result.
//
//export SkipiCoreDesktopIsRunning
func SkipiCoreDesktopIsRunning(handle C.uint64_t) C.int32_t {
	return cInt32(func() (int32, error) {
		running, err := desktopRuntime.IsRunning(desktopbridge.Handle(handle))
		if err != nil {
			return -1, err
		}
		if running {
			return 1, nil
		}
		return 0, nil
	})
}

// SkipiCoreDesktopQueryTrafficStats returns an owned JSON traffic snapshot, or
// NULL on error. Consult SkipiCoreDesktopLastError after a NULL result.
//
//export SkipiCoreDesktopQueryTrafficStats
func SkipiCoreDesktopQueryTrafficStats(handle C.uint64_t) *C.char {
	return cString(func() (string, error) {
		return desktopRuntime.QueryTrafficStats(desktopbridge.Handle(handle))
	})
}

// SkipiCoreDesktopMeasureDelay returns the in-process delay result in
// milliseconds, or -1 on error. Consult SkipiCoreDesktopLastError after -1.
//
//export SkipiCoreDesktopMeasureDelay
func SkipiCoreDesktopMeasureDelay(handle C.uint64_t, targetURL *C.char) C.int64_t {
	return cInt64(func() (int64, error) {
		target, err := requiredCString(targetURL, "delay target URL")
		if err != nil {
			return -1, err
		}
		return desktopRuntime.MeasureDelay(desktopbridge.Handle(handle), target)
	})
}

// SkipiCoreDesktopReadMemoryStats returns an owned JSON memory snapshot.
//
//export SkipiCoreDesktopReadMemoryStats
func SkipiCoreDesktopReadMemoryStats() *C.char {
	return cString(func() (string, error) {
		return desktopRuntime.ReadMemoryStats(), nil
	})
}

// SkipiCoreDesktopForceFreeMemory asks Go to release unused memory. It returns
// NULL on success, otherwise an owned error string.
//
//export SkipiCoreDesktopForceFreeMemory
func SkipiCoreDesktopForceFreeMemory() *C.char {
	return cError(func() error {
		desktopRuntime.ForceFreeMemory()
		return nil
	})
}

// SkipiCoreDesktopLastError returns a diagnostic string for the last failed C
// ABI call. The caller owns the returned string and must release it.
//
//export SkipiCoreDesktopLastError
func SkipiCoreDesktopLastError() *C.char {
	return C.CString(lastError())
}

// SkipiCoreDesktopFreeString releases a string returned by this C ABI.
//
//export SkipiCoreDesktopFreeString
func SkipiCoreDesktopFreeString(value *C.char) {
	if value != nil {
		C.free(unsafe.Pointer(value))
	}
}

func cError(action func() error) (result *C.char) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err := panicError(recovered)
			setLastError(err)
			result = C.CString(err.Error())
		}
	}()
	if err := action(); err != nil {
		setLastError(err)
		return C.CString(err.Error())
	}
	clearLastError()
	return nil
}

func cString(action func() (string, error)) (result *C.char) {
	defer func() {
		if recovered := recover(); recovered != nil {
			setLastError(panicError(recovered))
			result = nil
		}
	}()
	value, err := action()
	if err != nil {
		setLastError(err)
		return nil
	}
	clearLastError()
	return C.CString(value)
}

func cInt32(action func() (int32, error)) (result C.int32_t) {
	defer func() {
		if recovered := recover(); recovered != nil {
			setLastError(panicError(recovered))
			result = -1
		}
	}()
	value, err := action()
	if err != nil {
		setLastError(err)
		return -1
	}
	clearLastError()
	return C.int32_t(value)
}

func cInt64(action func() (int64, error)) (result C.int64_t) {
	defer func() {
		if recovered := recover(); recovered != nil {
			setLastError(panicError(recovered))
			result = -1
		}
	}()
	value, err := action()
	if err != nil {
		setLastError(err)
		return -1
	}
	clearLastError()
	return C.int64_t(value)
}

func requiredCString(value *C.char, field string) (string, error) {
	if value == nil {
		return "", fmt.Errorf("%s must not be NULL", field)
	}
	result := C.GoString(value)
	if result == "" {
		return "", fmt.Errorf("%s must not be blank", field)
	}
	return result, nil
}

func panicError(recovered any) error {
	return fmt.Errorf("SKIPI Core desktop ABI recovered panic: %v", recovered)
}

func setLastError(err error) {
	desktopErrors.Lock()
	defer desktopErrors.Unlock()
	desktopErrors.message = err.Error()
}

func clearLastError() {
	desktopErrors.Lock()
	defer desktopErrors.Unlock()
	desktopErrors.message = ""
}

func lastError() string {
	desktopErrors.Lock()
	defer desktopErrors.Unlock()
	return desktopErrors.message
}
