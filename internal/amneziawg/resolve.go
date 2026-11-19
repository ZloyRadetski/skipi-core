// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package amneziawg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	endpointLookupTimeout      = 3 * time.Second
	systemDNSLookupTimeout     = time.Second
	configuredDNSLookupTimeout = time.Second
)

type HostLookup func(context.Context, string) ([]netip.Addr, error)

// LookupHostWithFallback gives Android's resolver a short first
// chance, then queries the raw DNS addresses configured for the AWG netstack.
// This matters on networks whose system resolver censors or cannot reach an
// otherwise valid peer hostname. The caller's deadline still bounds both
// attempts together.
func LookupHostWithFallback(
	ctx context.Context,
	host string,
	systemLookup HostLookup,
	configuredDNSLookup HostLookup,
) ([]netip.Addr, error) {
	systemCtx, cancelSystemLookup := context.WithTimeout(ctx, systemDNSLookupTimeout)
	systemAddresses, systemErr := systemLookup(systemCtx, host)
	cancelSystemLookup()
	if usable := usableAddresses(systemAddresses); len(usable) > 0 {
		return usable, nil
	}
	if systemErr == nil {
		systemErr = errors.New("returned no usable IP addresses")
	}

	configuredAddresses, configuredErr := configuredDNSLookup(ctx, host)
	if usable := usableAddresses(configuredAddresses); len(usable) > 0 {
		return usable, nil
	}
	if configuredErr == nil {
		configuredErr = errors.New("returned no usable IP addresses")
	}
	return nil, fmt.Errorf("system DNS: %w; configured DNS: %w", systemErr, configuredErr)
}

func LookupHostWithConfiguredDNS(
	ctx context.Context,
	host string,
	dnsServers []netip.Addr,
) ([]netip.Addr, error) {
	var lookupErrors []error
	for _, server := range dnsServers {
		server = server.Unmap()
		if !server.IsValid() || server.IsUnspecified() {
			continue
		}
		resolverAddress := net.JoinHostPort(server.String(), "53")
		resolver := &net.Resolver{
			PreferGo:     true,
			StrictErrors: true,
			Dial: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(dialCtx, network, resolverAddress)
			},
		}
		lookupCtx, cancelLookup := context.WithTimeout(ctx, configuredDNSLookupTimeout)
		addresses, err := resolver.LookupNetIP(lookupCtx, "ip", host)
		cancelLookup()
		if usable := usableAddresses(addresses); len(usable) > 0 {
			return usable, nil
		}
		if err == nil {
			err = errors.New("returned no usable IP addresses")
		}
		lookupErrors = append(lookupErrors, fmt.Errorf("%s: %w", server, err))
		if ctx.Err() != nil {
			break
		}
	}
	if len(lookupErrors) == 0 {
		return nil, errors.New("no usable configured DNS servers")
	}
	return nil, errors.Join(lookupErrors...)
}

func usableAddresses(addresses []netip.Addr) []netip.Addr {
	usable := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if address.IsValid() && !address.IsUnspecified() {
			usable = append(usable, address)
		}
	}
	return usable
}

func ResolveEndpoint(
	raw string,
	lookup func(context.Context, string) ([]netip.Addr, error),
) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil || strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("invalid endpoint %q", raw)
	}
	portValue, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portValue == 0 {
		return "", fmt.Errorf("invalid endpoint port in %q", raw)
	}
	if address, err := netip.ParseAddr(host); err == nil && address.IsValid() && !address.IsUnspecified() {
		return net.JoinHostPort(address.Unmap().String(), port), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), endpointLookupTimeout)
	defer cancel()
	addresses, err := lookup(ctx, host)
	if err != nil {
		return "", fmt.Errorf("lookup %q: %w", host, err)
	}
	var firstIPv6 netip.Addr
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || address.IsUnspecified() {
			continue
		}
		if address.Is4() {
			return net.JoinHostPort(address.String(), port), nil
		}
		if !firstIPv6.IsValid() {
			firstIPv6 = address
		}
	}
	if firstIPv6.IsValid() {
		return net.JoinHostPort(firstIPv6.String(), port), nil
	}
	return "", fmt.Errorf("lookup %q returned no usable IP addresses", host)
}
