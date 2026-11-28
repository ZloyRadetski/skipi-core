// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package egress

// bindsLinkItself reports whether a dial must bind its link itself instead of handing the name to Xray's dialer.
// While the TUN's controller is in place, Xray's dialer runs it first and binds the socket to the physical
// interface; applying the link as a socket option afterwards is a second SO_BINDTODEVICE, which the kernel refuses
// (EPERM) for a socket that is already bound unless the process has CAP_NET_RAW. Such a dial binds the socket to
// the link on its own, as a link owned by the host does, and Xray's controllers stay out of it.
func bindsLinkItself() bool { return controller.Load() != nil }
