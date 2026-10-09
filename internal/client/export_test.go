package client

import "net/netip"

func LocalEndpointsForTest() []string { return localEndpoints(1, netip.Prefix{}) }
