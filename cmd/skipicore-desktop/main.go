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
	"github.com/ZloyRadetski/skipi-core/desktop/notify"
	"github.com/ZloyRadetski/skipi-core/desktop/tunhost"
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

// AmneziaWG's peer sockets follow Xray's: pinned to the physical interface while a TUN is up.
func init() { desktopbridge.SetSocketProtector(tunhost.Protector{}) }

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

// SkipiCoreDesktopStartSession starts a whole tunnel session from a plan JSON:
// {"xrayConfig": "...", "amneziaWg": {"config": "...", "socksPort": 10808}, "connectionLog": true}.
// amneziaWg is optional; Core starts it, waits for its SOCKS listener and then starts Xray, and
// Stop / ForceStop stop both. It returns NULL on success, otherwise an owned error string.
//
//export SkipiCoreDesktopStartSession
func SkipiCoreDesktopStartSession(handle C.uint64_t, planJSON *C.char, tunFD C.int64_t) *C.char {
	return cError(func() error {
		plan, err := requiredCString(planJSON, "session plan")
		if err != nil {
			return err
		}
		return desktopRuntime.StartSession(desktopbridge.Handle(handle), plan, int64(tunFD))
	})
}

// SkipiCoreDesktopSessionState returns 0 idle, 1 starting, 2 running, 3 stopping, and -1 for an
// unknown handle (see SkipiCoreDesktopLastError). It never waits on a slow start or stop.
//
//export SkipiCoreDesktopSessionState
func SkipiCoreDesktopSessionState(handle C.uint64_t) C.int32_t {
	return cInt32(func() (int32, error) {
		state, err := desktopRuntime.SessionState(desktopbridge.Handle(handle))
		if err != nil {
			return -1, err
		}
		return int32(state), nil
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

// SkipiCoreDesktopStopWithTimeout stops a controller, waiting at most timeout_millis for Xray
// to close (non-positive: 5000). On a timeout the controller is detached anyway and the
// returned error contains "timed out"; SkipiCoreDesktopAbandonedInstances then counts the
// instance until its Close returns. It returns NULL on success, otherwise an owned error string.
//
//export SkipiCoreDesktopStopWithTimeout
func SkipiCoreDesktopStopWithTimeout(handle C.uint64_t, timeoutMillis C.int64_t) *C.char {
	return cError(func() error {
		return desktopRuntime.StopWithTimeout(desktopbridge.Handle(handle), int64(timeoutMillis))
	})
}

// SkipiCoreDesktopForceStop is the emergency stop: it never waits on a hung start or stop,
// aborts a start in flight, and also stops AmneziaWG. It returns NULL on success, otherwise an
// owned error string ("timed out" when something had to be abandoned).
//
//export SkipiCoreDesktopForceStop
func SkipiCoreDesktopForceStop(handle C.uint64_t) *C.char {
	return cError(func() error {
		return desktopRuntime.ForceStop(desktopbridge.Handle(handle))
	})
}

// SkipiCoreDesktopAbandonedInstances returns how many Xray instances or AmneziaWG runners had
// their stop given up on and have not finished closing. Non-zero means the process is dirty
// and should be restarted.
//
//export SkipiCoreDesktopAbandonedInstances
func SkipiCoreDesktopAbandonedInstances() C.int64_t {
	return C.int64_t(desktopRuntime.AbandonedInstances())
}

// SkipiCoreDesktopTunOpen brings up the TUN interface described by a JSON plan
// ({"name","mtu","addresses","routes","dns"}; "dns" is optional and makes the
// system resolve through the tunnel) and returns the attached tun file descriptor, or -1 with SkipiCoreDesktopLastError set. The descriptor stays owned
// by SKIPI Core until SkipiCoreDesktopTunClose.
//
//export SkipiCoreDesktopTunOpen
func SkipiCoreDesktopTunOpen(planJSON *C.char) C.int64_t {
	return cInt64(func() (int64, error) {
		plan, err := requiredCString(planJSON, "TUN plan")
		if err != nil {
			return -1, err
		}
		fd, err := tunhost.Open(plan)
		return int64(fd), err
	})
}

// SkipiCoreDesktopTunProbe returns NULL when a TUN session can be opened on this machine,
// otherwise an owned string explaining why not.
//
//export SkipiCoreDesktopTunProbe
func SkipiCoreDesktopTunProbe() *C.char {
	return cError(tunhost.Probe)
}

// SkipiCoreDesktopTunPrepare binds SKIPI Core's own outbound sockets to the physical interface.
// Call it before SkipiCoreDesktopStart so no connection of the session is made without the
// binding; SkipiCoreDesktopTunClose undoes it. It returns NULL on success.
//
//export SkipiCoreDesktopTunPrepare
func SkipiCoreDesktopTunPrepare(interfaceName *C.char) *C.char {
	return cError(func() error {
		name, err := requiredCString(interfaceName, "interface name")
		if err != nil {
			return err
		}
		return tunhost.Prepare(name)
	})
}

// SkipiCoreDesktopNotify shows a desktop notification. It returns NULL
// on success, otherwise why it could not be shown (for example, no notification service runs).
//
//export SkipiCoreDesktopNotify
func SkipiCoreDesktopNotify(summary *C.char, body *C.char) *C.char {
	return cError(func() error {
		title, err := requiredCString(summary, "notification summary")
		if err != nil {
			return err
		}
		text := ""
		if body != nil {
			text = C.GoString(body)
		}
		return notify.Show(title, text)
	})
}

// SkipiCoreDesktopTunClose ends the TUN session. It returns NULL on success
// and is a no-op when no session is open.
//
//export SkipiCoreDesktopTunClose
func SkipiCoreDesktopTunClose() *C.char {
	return cError(tunhost.Close)
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

// SkipiCoreDesktopStartAmneziaWg starts the AmneziaWG runner and its loopback SOCKS
// listener on socksPort, before Core is started. It returns NULL on success,
// otherwise an owned error string.
//
//export SkipiCoreDesktopStartAmneziaWg
func SkipiCoreDesktopStartAmneziaWg(configJSON *C.char, socksPort C.int32_t) *C.char {
	return cError(func() error {
		config, err := requiredCString(configJSON, "AmneziaWG configuration")
		if err != nil {
			return err
		}
		return desktopRuntime.StartAmneziaWg(config, int(socksPort))
	})
}

// SkipiCoreDesktopStopAmneziaWg stops the AmneziaWG runner. It returns NULL on
// success, otherwise an owned error string.
//
//export SkipiCoreDesktopStopAmneziaWg
func SkipiCoreDesktopStopAmneziaWg() *C.char {
	return cError(func() error {
		return desktopRuntime.StopAmneziaWg()
	})
}

// SkipiCoreDesktopIsAmneziaWgRunning returns 1 while the AmneziaWG runner is
// active and 0 otherwise.
//
//export SkipiCoreDesktopIsAmneziaWgRunning
func SkipiCoreDesktopIsAmneziaWgRunning() C.int32_t {
	if desktopRuntime.IsAmneziaWgRunning() {
		return 1
	}
	return 0
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

// SkipiCoreDesktopQueryTunnelStats returns an owned JSON snapshot of the HEV TUN counters
// ({"txPackets","txBytes","rxPackets","rxBytes"}), or NULL on error. The counters are zero when
// no HEV TUN runs, and always zero on Windows, where hev is a separate process.
//
//export SkipiCoreDesktopQueryTunnelStats
func SkipiCoreDesktopQueryTunnelStats(handle C.uint64_t) *C.char {
	return cString(func() (string, error) {
		return desktopRuntime.QueryTunnelStats(desktopbridge.Handle(handle))
	})
}

// SkipiCoreDesktopSetConnectionLogEnabled switches the connection log of a controller.
// Returns NULL on success.
//
//export SkipiCoreDesktopSetConnectionLogEnabled
func SkipiCoreDesktopSetConnectionLogEnabled(handle C.uint64_t, enabled C.int32_t) *C.char {
	return cError(func() error {
		return desktopRuntime.SetConnectionLogEnabled(desktopbridge.Handle(handle), enabled != 0)
	})
}

// SkipiCoreDesktopReadConnectionLog returns an owned JSON snapshot of the routed connections
// newer than afterSeq, or NULL on error.
//
//export SkipiCoreDesktopReadConnectionLog
func SkipiCoreDesktopReadConnectionLog(handle C.uint64_t, afterSeq C.int64_t) *C.char {
	return cString(func() (string, error) {
		return desktopRuntime.ReadConnectionLog(desktopbridge.Handle(handle), int64(afterSeq))
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

// SkipiCoreDesktopMeasureOutboundDelay returns the delay of one outbound, in
// milliseconds, through an isolated Core instance, or -1 on error. Consult
// SkipiCoreDesktopLastError after -1.
//
//export SkipiCoreDesktopMeasureOutboundDelay
func SkipiCoreDesktopMeasureOutboundDelay(configJSON *C.char, targetURL *C.char) C.int64_t {
	return cInt64(func() (int64, error) {
		config, err := requiredCString(configJSON, "probe configuration")
		if err != nil {
			return -1, err
		}
		target, err := requiredCString(targetURL, "delay target URL")
		if err != nil {
			return -1, err
		}
		return desktopRuntime.MeasureOutboundDelay(config, target)
	})
}

// SkipiCoreDesktopMeasureTcpDelay returns the time of one TCP connect to
// host:port in milliseconds, dialed like Core's own sockets (so the physical
// interface binding of a tunnel session applies), or -1 on error. Consult
// SkipiCoreDesktopLastError after -1.
//
//export SkipiCoreDesktopMeasureTcpDelay
func SkipiCoreDesktopMeasureTcpDelay(host *C.char, port C.int32_t, timeoutMillis C.int32_t) C.int64_t {
	return cInt64(func() (int64, error) {
		target, err := requiredCString(host, "TCP probe host")
		if err != nil {
			return -1, err
		}
		return desktopRuntime.MeasureTcpDelay(target, int(port), int(timeoutMillis))
	})
}

// SkipiCoreDesktopMeasureOutboundDelays measures every outbound named in candidate_tags (comma
// separated) of one config through a single isolated Core instance and returns an owned JSON
// object of tag to milliseconds (-1 for a tag that failed), or NULL on error (see
// SkipiCoreDesktopLastError).
//
//export SkipiCoreDesktopMeasureOutboundDelays
func SkipiCoreDesktopMeasureOutboundDelays(configJSON *C.char, candidateTags *C.char, targetURL *C.char, timeoutMillis C.int64_t) *C.char {
	return cString(func() (string, error) {
		config, err := requiredCString(configJSON, "probe configuration")
		if err != nil {
			return "", err
		}
		target, err := requiredCString(targetURL, "delay target URL")
		if err != nil {
			return "", err
		}
		return desktopRuntime.MeasureOutboundDelays(config, C.GoString(candidateTags), target, int64(timeoutMillis))
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
