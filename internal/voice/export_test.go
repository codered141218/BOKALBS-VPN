package voice

import (
	"context"
	"net"
	"net/http"
	"net/netip"
)

type httpTransport = http.Transport

func dialFrom(ip netip.Addr) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: ip.AsSlice()}}
	return d.DialContext
}
