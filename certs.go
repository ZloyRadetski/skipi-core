// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package skipicore

import "github.com/ZloyRadetski/skipi-core/internal/certfetch"

// FetchTlsCertSha256 extracts the SHA-256 fingerprint of a remote server's TLS certificate.
func FetchTlsCertSha256(requestJSON string) string {
	return certfetch.TLS(requestJSON)
}

// FetchQuicCertSha256 extracts the SHA-256 fingerprint of a remote server's QUIC/HTTP3 certificate.
func FetchQuicCertSha256(requestJSON string) string {
	return certfetch.QUIC(requestJSON)
}
