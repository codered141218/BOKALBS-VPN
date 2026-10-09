package client

import (
	"net/netip"

	"github.com/codered141218/bokalbs-vpn/internal/netutil"
)

func LocalEndpointsForTest() []string { return netutil.LocalEndpoints(1, netip.Prefix{}) }
