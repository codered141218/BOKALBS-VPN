package client_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/client"
	"github.com/codered141218/bokalbs-vpn/internal/proto"
	"github.com/codered141218/bokalbs-vpn/internal/rendezvous/rvtest"
	"github.com/codered141218/bokalbs-vpn/internal/server"
	"github.com/codered141218/bokalbs-vpn/internal/tunnel"
)

// fakeDev stands in for the virtual network adapter.
type fakeDev struct {
	addr    netip.Prefix
	toNet   chan []byte // packets "Windows" sends into the VPN
	fromNet chan []byte // packets the VPN delivers to "Windows"
	once    sync.Once
	closed  chan struct{}
}

func (d *fakeDev) ReadPacket(buf []byte) (int, error) {
	select {
	case p := <-d.toNet:
		return copy(buf, p), nil
	case <-d.closed:
		return 0, tunnel.ErrClosed
	}
}

func (d *fakeDev) WritePacket(p []byte) error {
	select {
	case d.fromNet <- append([]byte(nil), p...):
	default:
	}
	return nil
}

func (d *fakeDev) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

// udpPacket builds a minimal IPv4/UDP packet.
func udpPacket(src, dst netip.Addr, port uint16, payload string) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	s, d := src.As4(), dst.As4()
	copy(p[12:], s[:])
	copy(p[16:], d[:])
	binary.BigEndian.PutUint16(p[20:], port)
	binary.BigEndian.PutUint16(p[22:], port)
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

type member struct {
	c   *client.Client
	dev chan *fakeDev
}

func (m *member) device(t *testing.T) *fakeDev {
	t.Helper()
	select {
	case d := <-m.dev:
		m.dev <- d
		return d
	case <-time.After(10 * time.Second):
		t.Fatal("device never opened")
		return nil
	}
}

func startServer(t *testing.T, ctx context.Context) string {
	t.Helper()
	srv, err := server.New(server.Config{Listen: "127.0.0.1:0", Network: "lan-party", Password: "hunter2", Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	go srv.Run(ctx)
	return srv.Addr().String()
}

func join(t *testing.T, ctx context.Context, addr, name, id, password string, relayOnly bool) *member {
	t.Helper()
	m := &member{dev: make(chan *fakeDev, 1)}
	c, err := client.Start(ctx, client.Config{
		Server: addr, Network: "lan-party", Password: password, Name: name, ClientID: id, RelayOnly: relayOnly,
		OpenDevice: func(a netip.Prefix) (tunnel.Device, error) {
			d := &fakeDev{addr: a, toNet: make(chan []byte, 64), fromNet: make(chan []byte, 64), closed: make(chan struct{})}
			select {
			case <-m.dev:
			default:
			}
			m.dev <- d
			return d, nil
		},
		Logf: func(f string, a ...any) { t.Logf(name+": "+f, a...) },
	})
	if err != nil {
		t.Fatal(err)
	}
	m.c = c
	t.Cleanup(c.Stop)
	return m
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func expectPacket(t *testing.T, d *fakeDev, want string) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case p := <-d.fromNet:
			if len(p) >= 28 && string(p[28:]) == want {
				return
			}
		case <-timeout:
			t.Fatalf("%s did not receive %q", d.addr, want)
		}
	}
}

func expectNoPacket(t *testing.T, d *fakeDev, unwanted string) {
	t.Helper()
	timeout := time.After(500 * time.Millisecond)
	for {
		select {
		case p := <-d.fromNet:
			if len(p) >= 28 && string(p[28:]) == unwanted {
				t.Fatalf("%s unexpectedly received %q", d.addr, unwanted)
			}
		case <-timeout:
			return
		}
	}
}

func testNetwork(t *testing.T, relayOnly bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := startServer(t, ctx)

	var ms []*member
	for i, name := range []string{"alice", "bob", "carol"} {
		ms = append(ms, join(t, ctx, addr, name, fmt.Sprintf("device-%d", i), "hunter2", relayOnly))
	}
	for _, m := range ms {
		waitFor(t, "connected with 2 peers", 15*time.Second, func() bool {
			st := m.c.Status()
			return st.State == client.StateConnected && len(st.Peers) == 2
		})
	}
	a, b, c := ms[0].device(t), ms[1].device(t), ms[2].device(t)
	if a.addr.Addr() == b.addr.Addr() || a.addr.Masked().String() != "10.77.0.0/24" {
		t.Fatalf("bad addresses %s %s", a.addr, b.addr)
	}

	// Unicast reaches only its destination.
	a.toNet <- udpPacket(a.addr.Addr(), b.addr.Addr(), 445, "files for bob")
	expectPacket(t, b, "files for bob")
	expectNoPacket(t, c, "files for bob")

	// A Warcraft III style LAN broadcast reaches everyone else.
	bcast := netip.MustParseAddr("255.255.255.255")
	c.toNet <- udpPacket(c.addr.Addr(), bcast, 6112, "w3 game search")
	expectPacket(t, a, "w3 game search")
	expectPacket(t, b, "w3 game search")
	b.toNet <- udpPacket(b.addr.Addr(), proto.LastAddr(b.addr), 6112, "subnet broadcast")
	expectPacket(t, a, "subnet broadcast")
	expectPacket(t, c, "subnet broadcast")

	// Spoofed source addresses are dropped.
	a.toNet <- udpPacket(c.addr.Addr(), b.addr.Addr(), 1, "spoofed")
	expectNoPacket(t, b, "spoofed")

	if relayOnly {
		for _, p := range ms[0].c.Status().Peers {
			if p.Direct {
				t.Fatal("direct connection in relay-only mode")
			}
		}
		return
	}
	if len(nonLoopback()) == 0 {
		t.Skip("no LAN address available to test direct connections")
	}
	for _, m := range ms {
		waitFor(t, "direct connections", 15*time.Second, func() bool {
			for _, p := range m.c.Status().Peers {
				if !p.Direct {
					return false
				}
			}
			return true
		})
	}
	a.toNet <- udpPacket(a.addr.Addr(), c.addr.Addr(), 6112, "direct hello")
	expectPacket(t, c, "direct hello")
}

func nonLoopback() []string {
	return client.LocalEndpointsForTest()
}

func TestNetworkDirect(t *testing.T) { testNetwork(t, false) }
func TestNetworkRelay(t *testing.T)  { testNetwork(t, true) }

func TestStableAddressAndWrongPassword(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := startServer(t, ctx)

	m := join(t, ctx, addr, "dave", "dave-pc", "hunter2", false)
	waitFor(t, "connected", 10*time.Second, func() bool { return m.c.Status().State == client.StateConnected })
	first := m.c.Status().IP
	other := join(t, ctx, addr, "erin", "erin-pc", "hunter2", false)
	waitFor(t, "connected", 10*time.Second, func() bool { return other.c.Status().State == client.StateConnected })
	m.c.Stop()

	again := join(t, ctx, addr, "dave", "dave-pc", "hunter2", false)
	waitFor(t, "reconnected", 10*time.Second, func() bool { return again.c.Status().State == client.StateConnected })
	if got := again.c.Status().IP; got != first {
		t.Fatalf("address changed on reconnect: %s -> %s", first, got)
	}

	bad := join(t, ctx, addr, "mallory", "mallory-pc", "wrong", false)
	time.Sleep(7 * time.Second)
	if st := bad.c.Status(); st.State == client.StateConnected {
		t.Fatal("connected with the wrong password")
	}
}

func TestServerRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	leases := t.TempDir() + "/leases.json"
	start := func(listen string) (string, context.CancelFunc) {
		sctx, scancel := context.WithCancel(ctx)
		srv, err := server.New(server.Config{Listen: listen, Network: "lan-party", Password: "hunter2", LeaseFile: leases, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.Listen(); err != nil {
			t.Fatal(err)
		}
		go srv.Run(sctx)
		return srv.Addr().String(), scancel
	}
	addr, stop := start("127.0.0.1:0")
	other := join(t, ctx, addr, "zed", "zed-pc", "hunter2", true)
	m := join(t, ctx, addr, "frank", "frank-pc", "hunter2", true)
	waitFor(t, "connected", 10*time.Second, func() bool { return m.c.Status().State == client.StateConnected })
	waitFor(t, "connected", 10*time.Second, func() bool { return other.c.Status().State == client.StateConnected })
	dev := m.device(t)
	ip := m.c.Status().IP

	stop()
	time.Sleep(200 * time.Millisecond)
	_, stop2 := start(addr) // same port: the "host" restarted the app
	defer stop2()

	// The client notices (via a Reset reply to its next packet) and rejoins.
	waitFor(t, "rejoined after server restart", 20*time.Second, func() bool {
		st := m.c.Status()
		return st.State == client.StateConnected && len(st.Peers) == 1
	})
	if got := m.c.Status().IP; got != ip {
		t.Fatalf("address changed after server restart: %s -> %s", ip, got)
	}
	if m.device(t) != dev {
		t.Fatal("adapter was recreated although the address did not change")
	}
	// The other member rejoins on its own schedule; keep sending until it is back.
	od := other.device(t)
	deadline := time.Now().Add(20 * time.Second)
	for {
		dev.toNet <- udpPacket(dev.addr.Addr(), od.addr.Addr(), 6112, "after restart")
		select {
		case p := <-od.fromNet:
			if string(p[28:]) == "after restart" {
				return
			}
		case <-time.After(500 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("no traffic after server restart")
		}
	}
}

func TestJoinWithoutServerAddress(t *testing.T) {
	ntfy := httptest.NewServer(rvtest.NewNtfy())
	defer ntfy.Close() // runs after cancel, which ends the open subscriptions
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stunConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer stunConn.Close()
	go rvtest.ServeSTUN(stunConn)
	stunServers := []string{stunConn.LocalAddr().String()}

	joinRV := func(name, id string) *member {
		m := &member{dev: make(chan *fakeDev, 1)}
		c, err := client.Start(ctx, client.Config{
			Network: "lan-party", Password: "hunter2", Name: name, ClientID: id,
			Rendezvous: ntfy.URL, STUNServers: stunServers,
			OpenDevice: func(a netip.Prefix) (tunnel.Device, error) {
				d := &fakeDev{addr: a, toNet: make(chan []byte, 64), fromNet: make(chan []byte, 64), closed: make(chan struct{})}
				m.dev <- d
				return d, nil
			},
			Logf: func(f string, a ...any) { t.Logf(name+": "+f, a...) },
		})
		if err != nil {
			t.Fatal(err)
		}
		m.c = c
		t.Cleanup(c.Stop)
		return m
	}

	// Nobody hosts yet: the player is told so and keeps trying.
	early := joinRV("early", "early-pc")
	waitFor(t, "no-host message", 10*time.Second, func() bool {
		return strings.Contains(early.c.Status().Message, "nobody is hosting")
	})

	srv, err := server.New(server.Config{Listen: "127.0.0.1:0", Network: "lan-party", Password: "hunter2",
		Rendezvous: ntfy.URL, STUNServers: stunServers, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	go srv.Run(ctx)
	waitFor(t, "host announced", 10*time.Second, func() bool { return srv.NAT().Announced })
	if nat := srv.NAT(); nat.Public != srv.Addr().String() || nat.Symmetric {
		t.Fatalf("unexpected NAT status %+v", nat)
	}

	late := joinRV("late", "late-pc")
	for _, m := range []*member{early, late} {
		waitFor(t, "connected through rendezvous", 30*time.Second, func() bool {
			st := m.c.Status()
			return st.State == client.StateConnected && len(st.Peers) == 1
		})
	}
	a, b := early.device(t), late.device(t)
	a.toNet <- udpPacket(a.addr.Addr(), proto.LastAddr(a.addr), 6112, "found you")
	expectPacket(t, b, "found you")
}
