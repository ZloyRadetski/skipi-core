// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build linux

package nmtun

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	nmService         = "org.freedesktop.NetworkManager"
	nmPath            = dbus.ObjectPath("/org/freedesktop/NetworkManager")
	activeConnection  = "org.freedesktop.NetworkManager.Connection.Active"
	stateActivated    = uint32(2)
	stateDeactivating = uint32(3)
	stateDeactivated  = uint32(4)
	startupTimeout    = 15 * time.Second
	startupPoll       = 25 * time.Millisecond
)

// Session is a tun interface NetworkManager created for this process. The fd stays valid until
// Close; the interface and its routes disappear when the session ends or the process dies.
type Session struct {
	conn   *dbus.Conn
	fd     int
	active dbus.ObjectPath
}

// FD returns the attached tun device. The caller must not close it.
func (s *Session) FD() int { return s.fd }

// Open asks NetworkManager for the interface described by plan and attaches to it. It returns once
// NetworkManager reports the connection activated, so addresses and routes are in place.
func Open(plan Plan) (*Session, error) {
	account, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("current user: %w", err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return nil, fmt.Errorf("current user id %q: %w", account.Uid, err)
	}
	settings, err := plan.Settings(uid, account.Username)
	if err != nil {
		return nil, err
	}

	// A private connection: closing it is what tells NetworkManager to tear the interface down.
	conn, err := dbus.SystemBusPrivate()
	if err != nil {
		return nil, fmt.Errorf("system bus: %w", err)
	}
	if err := conn.Auth(nil); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("system bus authentication: %w", err)
	}
	if err := conn.Hello(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("system bus handshake: %w", err)
	}

	options := map[string]dbus.Variant{
		"persist":         dbus.MakeVariant("volatile"),
		"bind-activation": dbus.MakeVariant("dbus-client"),
	}
	var connectionPath, activePath dbus.ObjectPath
	var result map[string]dbus.Variant
	call := conn.Object(nmService, nmPath).Call(
		nmService+".AddAndActivateConnection2", 0,
		settings, dbus.ObjectPath("/"), dbus.ObjectPath("/"), options,
	)
	if err := call.Store(&connectionPath, &activePath, &result); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("NetworkManager refused the TUN connection: %w", err)
	}

	session := &Session{conn: conn, fd: -1, active: activePath}
	deadline := time.Now().Add(startupTimeout)
	if err := session.attach(plan.Name, deadline); err != nil {
		_ = session.Close()
		return nil, err
	}
	if err := session.waitActivated(deadline); err != nil {
		_ = session.Close()
		return nil, err
	}
	return session, nil
}

// attach opens the tun device NetworkManager created. Until the device exists the kernel refuses
// to create it for an unprivileged caller, so refusals are retried until the deadline.
func (s *Session) attach(name string, deadline time.Time) error {
	var last error
	for time.Now().Before(deadline) {
		if _, err := os.Stat("/sys/class/net/" + name); err == nil {
			fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
			if err != nil {
				return fmt.Errorf("open /dev/net/tun: %w", err)
			}
			request, err := unix.NewIfreq(name)
			if err != nil {
				_ = unix.Close(fd)
				return err
			}
			request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
			err = unix.IoctlIfreq(fd, unix.TUNSETIFF, request)
			if err == nil {
				s.fd = fd
				return nil
			}
			last = err
			_ = unix.Close(fd)
		}
		time.Sleep(startupPoll)
	}
	if last != nil {
		return fmt.Errorf("attach to %s: %w", name, last)
	}
	return fmt.Errorf("NetworkManager did not create %s in time", name)
}

func (s *Session) waitActivated(deadline time.Time) error {
	object := s.conn.Object(nmService, s.active)
	for time.Now().Before(deadline) {
		property, err := object.GetProperty(activeConnection + ".State")
		if err != nil {
			return fmt.Errorf("connection state: %w", err)
		}
		state, ok := property.Value().(uint32)
		if !ok {
			return errors.New("unexpected connection state type")
		}
		switch state {
		case stateActivated:
			return nil
		case stateDeactivating, stateDeactivated:
			return errors.New("NetworkManager deactivated the TUN connection")
		}
		time.Sleep(startupPoll)
	}
	return errors.New("NetworkManager did not activate the TUN connection in time")
}

// Close releases the device and ends the session; NetworkManager removes the interface.
func (s *Session) Close() error {
	var first error
	if s.fd >= 0 {
		first = unix.Close(s.fd)
		s.fd = -1
	}
	if s.conn != nil {
		_ = s.conn.Object(nmService, nmPath).Call(nmService+".DeactivateConnection", 0, s.active).Err
		if err := s.conn.Close(); first == nil {
			first = err
		}
		s.conn = nil
	}
	return first
}
