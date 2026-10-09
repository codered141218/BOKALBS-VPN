package stun

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	from := netip.MustParseAddrPort("203.0.113.7:40123")
	tx, req := request()
	if !IsRequest(req) || !IsMessage(req) {
		t.Fatal("request not recognised")
	}
	gotTx, mapped, ok := parseResponse(BuildResponse(req, from))
	if !ok || gotTx != tx || mapped != from {
		t.Fatalf("got %v %v %v", ok, mapped, gotTx == tx)
	}
	hello := make([]byte, 50)
	hello[0], hello[1] = 1, 1
	if IsMessage(hello) {
		t.Fatal("VPN hello mistaken for STUN")
	}
}

func TestDiscoverWithLocalServer(t *testing.T) {
	srv, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer srv.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := srv.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if IsRequest(buf[:n]) {
				srv.WriteToUDPAddrPort(BuildResponse(buf[:n], from), from)
			}
		}
	}()
	sock, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer sock.Close()
	var pr Prober
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := sock.Read(buf)
			if err != nil {
				return
			}
			pr.Handle(buf[:n])
		}
	}()
	send := func(p []byte, to netip.AddrPort) error { _, err := sock.WriteToUDPAddrPort(p, to); return err }
	res, err := pr.Discover(context.Background(), send, []string{srv.LocalAddr().String(), srv.LocalAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Public.String() != sock.LocalAddr().String() || res.Symmetric {
		t.Fatalf("got %+v want %s", res, sock.LocalAddr())
	}
}
