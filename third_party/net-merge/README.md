# net-merge

`desktop/multilink` is based on [net-merge](https://github.com/net-merge/net-merge) by Rohit Mahto,
MIT License (`LICENSE` in this folder). The scheduler, the probes, the speed limits, the phone handling,
the adapter discovery and their tests come from net-merge's `internal/engine` and `internal/nics`;
the files that started from it say so at the top.

Changed for SKIPI: adapters are keyed by their GUID instead of their name, a connection is handed to the
scheduler from Xray's system dialer (`desktop/egress`) instead of a TUN of its own, and the SOCKS5 and
TUN front-ends, the tray and the CLI are not used.
