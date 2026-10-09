// Package netutil holds small networking helpers shared by client and server.
package netutil

import (
	"net"
	"net/netip"
)

// LocalEndpoints lists this computer's LAN IPv4 addresses with port, so
// members behind the same router can talk to each other directly.
func LocalEndpoints(port int, exclude netip.Prefix) []string {
	var out []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || (exclude.IsValid() && exclude.Contains(ip)) {
			continue
		}
		out = append(out, netip.AddrPortFrom(ip, uint16(port)).String())
		if len(out) == 6 {
			break
		}
	}
	return out
}

// ParseEndpoints keeps the valid IPv4 ip:port strings, up to max.
func ParseEndpoints(in []string, max int) []netip.AddrPort {
	var out []netip.AddrPort
	for _, e := range in {
		ap, err := netip.ParseAddrPort(e)
		if err != nil || !ap.Addr().Is4() || ap.Port() == 0 {
			continue
		}
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		dup := false
		for _, o := range out {
			dup = dup || o == ap
		}
		if !dup {
			out = append(out, ap)
		}
		if len(out) == max {
			break
		}
	}
	return out
}
