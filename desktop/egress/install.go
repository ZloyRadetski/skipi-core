// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package egress

import (
	"sync/atomic"
	"syscall"

	"github.com/xtls/xray-core/transport/internet"
)

// Controller works on a socket before it connects, as Xray's dialer controllers do.
type Controller func(network, address string, c syscall.RawConn) error

var (
	system     = NewDialer(&internet.DefaultSystemDialer{})
	controller atomic.Pointer[Controller]
	installErr error
)

// Xray accepts dialer controllers only while its default dialer is the effective one, so the one controller SKIPI
// needs is registered first and the SKIPI dialer is put in place after it. Both happen while the package loads,
// before any Core session can dial; everything later only swaps what the controller and the dialer do.
func init() {
	installErr = internet.RegisterDialerController(func(network, address string, c syscall.RawConn) error {
		if ctl := controller.Load(); ctl != nil {
			return (*ctl)(network, address, c)
		}
		return nil
	})
	if installErr == nil {
		internet.UseAlternativeSystemDialer(system)
	}
}

// InstallError reports why the SKIPI dialer could not be put in place; nil when it is.
func InstallError() error { return installErr }

// SetController makes ctl run on every socket Xray dials (the TUN's binding to the physical link); nil removes it.
func SetController(ctl Controller) {
	if ctl == nil {
		controller.Store(nil)
		return
	}
	controller.Store(&ctl)
}

// System is the dialer Xray uses for its own connections.
func System() *Dialer { return system }
