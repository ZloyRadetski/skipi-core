// Based on net-merge (https://github.com/net-merge/net-merge), Copyright (c) 2026 Rohit Mahto, MIT License;
// see third_party/net-merge. Changes for SKIPI Core: Copyright 2026, Radetski, GPL-3.0.

// Package multilink spreads SKIPI Core's new connections over every network link that reaches the internet:
// Wi-Fi, Ethernet and phone tethers together. Each connection stays on the link it was given, so one
// connection is never faster than one link; many connections (downloads, browsers, the proxy's own connections
// to its servers) add the links up. The scheduler sends a new connection to the link with the fewest busy
// connections for its measured speed, keeps dead links out by probing them, and can cap a link or go easy on a
// phone hotspot. Package egress hands Xray's dials to it.
package multilink
