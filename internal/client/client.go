// Package client implements a BOKALBS VPN network member.
//
// A client connects to the network's server, gets a virtual IP address and
// creates the virtual network adapter. Traffic to another member goes
// directly to that member when UDP hole punching succeeds, and through the
// server otherwise. Broadcasts (used by LAN games to find each other) are
// sent to the server, which delivers them to everyone.
package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/netutil"
	"github.com/codered141218/bokalbs-vpn/internal/proto"
	"github.com/codered141218/bokalbs-vpn/internal/rendezvous"
	"github.com/codered141218/bokalbs-vpn/internal/stun"
	"github.com/codered141218/bokalbs-vpn/internal/tunnel"
)

const (
	pingInterval       = 5 * time.Second
	keepInterval       = 10 * time.Second
	serverTimeout      = 30 * time.Second
	punchInterval      = 2 * time.Second
	directTimeout      = 15 * time.Second
	handshakeAttempts  = 5
	punchAttempts      = 16 // when connecting through the rendezvous service
	handshakeRetryWait = time.Second
)

// Config configures a client.
type Config struct {
	Server     string // "host:port" of the network's server
	Network    string
	Password   string
	Name       string // nickname shown to other members
	ClientID   string // stable random id of this device; keeps the same IP across reconnects
	ListenPort int    // local UDP port, 0 = any
	AppVersion string
	RelayOnly  bool // never try direct peer-to-peer connections

	// When Server is empty the host is found through this rendezvous
	// service (see package rendezvous), so nobody needs port forwarding.
	Rendezvous  string
	STUNServers []string // defaults to stun.Servers()

	// OpenDevice creates the virtual adapter once the address is known.
	// Defaults to tunnel.Open.
	OpenDevice func(addr netip.Prefix) (tunnel.Device, error)
	Logf       func(format string, args ...any)
}

// State of the connection, for display.
type State string

const (
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateReconnecting State = "reconnecting"
	StateStopped      State = "stopped"
	StateFailed       State = "failed"
)

// PeerStatus describes another member as seen by this client.
type PeerStatus struct {
	Name     string  `json:"name"`
	IP       string  `json:"ip"`
	Direct   bool    `json:"direct"`
	Endpoint string  `json:"endpoint,omitempty"`
	RTTms    float64 `json:"rttMs,omitempty"`
}

// Status is a snapshot of the client.
type Status struct {
	State       State        `json:"state"`
	Message     string       `json:"message,omitempty"`
	IP          string       `json:"ip,omitempty"`
	Subnet      string       `json:"subnet,omitempty"`
	Public      string       `json:"public,omitempty"`
	ServerRTTms float64      `json:"serverRttMs,omitempty"`
	Peers       []PeerStatus `json:"peers"`

	// LAN game broadcasts this PC sent into the VPN and received from it,
	// to see whether games such as Warcraft III can find each other.
	BroadcastsSent     uint64 `json:"broadcastsSent"`
	BroadcastsReceived uint64 `json:"broadcastsReceived"`
}

type peer struct {
	info       proto.PeerInfo
	ip         netip.Addr
	sealer     *proto.Sealer
	opener     *proto.Opener
	candidates []netip.AddrPort

	direct   netip.AddrPort // address where a round trip succeeded
	lastPong time.Time
	lastPing time.Time
	rtt      time.Duration
}

func (p *peer) directAlive(now time.Time) bool {
	return p.direct.IsValid() && now.Sub(p.lastPong) < directTimeout
}

type handshake struct {
	eph    *proto.Ephemeral
	cands  []netip.AddrPort // addresses the server may answer from
	result chan handshakeResult
}

type handshakeResult struct {
	sid  uint32
	keys *proto.SessionKeys
	from netip.AddrPort
}

// Client is a running network member.
type Client struct {
	bcastOut atomic.Uint64
	bcastIn  atomic.Uint64

	cfg    Config
	psk    []byte
	conn   *net.UDPConn
	prober stun.Prober
	cancel context.CancelFunc
	done   chan struct{}

	mu           sync.Mutex
	state        State
	message      string
	server       netip.AddrPort
	hs           *handshake
	sid          uint32
	sealer       *proto.Sealer
	opener       *proto.Opener
	lastRecv     time.Time
	serverRTT    time.Duration
	addr         netip.Prefix
	public       string
	dev          tunnel.Device
	peers        map[uint32]*peer
	peersByIP    map[netip.Addr]*peer
	peersVersion uint64

	configCh chan *proto.Control
	lostCh   chan struct{}
	fatalCh  chan error
}

// Start launches the client in the background. Use Status to follow it and
// Stop to disconnect.
func Start(parent context.Context, cfg Config) (*Client, error) {
	if cfg.Network == "" || cfg.Password == "" {
		return nil, errors.New("network name and password are required")
	}
	if cfg.Server == "" && cfg.Rendezvous == "" {
		return nil, errors.New("a server address or a rendezvous service is required")
	}
	if len(cfg.STUNServers) == 0 {
		cfg.STUNServers = stun.Servers()
	}
	if cfg.ClientID == "" {
		return nil, errors.New("client id is required")
	}
	if cfg.OpenDevice == nil {
		cfg.OpenDevice = tunnel.Open
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: cfg.ListenPort})
	if err != nil {
		return nil, fmt.Errorf("cannot open UDP port: %w", err)
	}
	_ = conn.SetReadBuffer(4 << 20)
	_ = conn.SetWriteBuffer(4 << 20)
	ctx, cancel := context.WithCancel(parent)
	c := &Client{
		cfg:       cfg,
		conn:      conn,
		cancel:    cancel,
		done:      make(chan struct{}),
		state:     StateConnecting,
		message:   "Preparing…",
		peers:     map[uint32]*peer{},
		peersByIP: map[netip.Addr]*peer{},
		configCh:  make(chan *proto.Control, 1),
		lostCh:    make(chan struct{}, 1),
		fatalCh:   make(chan error, 1),
	}
	go c.run(ctx)
	return c, nil
}

// Stop disconnects and removes the virtual adapter.
func (c *Client) Stop() {
	c.cancel()
	<-c.done
}

// Done is closed when the client has stopped (by Stop or a fatal error).
func (c *Client) Done() <-chan struct{} { return c.done }

// Status returns a snapshot for display.
func (c *Client) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	st := Status{State: c.state, Message: c.message, Public: c.public, Peers: []PeerStatus{},
		BroadcastsSent: c.bcastOut.Load(), BroadcastsReceived: c.bcastIn.Load()}
	if c.addr.IsValid() {
		st.IP = c.addr.Addr().String()
		st.Subnet = c.addr.Masked().String()
	}
	if c.serverRTT > 0 {
		st.ServerRTTms = ms(c.serverRTT)
	}
	for _, p := range c.peers {
		ps := PeerStatus{Name: p.info.Name, IP: p.info.IP}
		if p.directAlive(now) {
			ps.Direct = true
			ps.Endpoint = p.direct.String()
			ps.RTTms = ms(p.rtt)
		}
		st.Peers = append(st.Peers, ps)
	}
	sort.Slice(st.Peers, func(i, j int) bool {
		a, _ := netip.ParseAddr(st.Peers[i].IP)
		b, _ := netip.ParseAddr(st.Peers[j].IP)
		return a.Less(b)
	})
	return st
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func (c *Client) setState(s State, msg string) {
	c.mu.Lock()
	c.state, c.message = s, msg
	c.mu.Unlock()
	c.cfg.Logf("client: %s: %s", s, msg)
}

func (c *Client) run(ctx context.Context) {
	defer close(c.done)
	go c.readLoop()

	err := c.loop(ctx)

	c.mu.Lock()
	sealer, server, dev := c.sealer, c.server, c.dev
	c.dev = nil
	c.mu.Unlock()
	if sealer != nil {
		bye := &proto.Control{Type: proto.MsgBye}
		_, _ = c.conn.WriteToUDPAddrPort(sealer.Seal(proto.KindControl, bye.Marshal()), server)
	}
	c.conn.Close()
	if dev != nil {
		dev.Close()
	}
	if err != nil {
		c.setState(StateFailed, err.Error())
	} else {
		c.setState(StateStopped, "Disconnected")
	}
}

// loop connects, and reconnects whenever the session is lost.
func (c *Client) loop(ctx context.Context) error {
	first := true
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return nil
		}
		if !first {
			c.setState(StateReconnecting, "Connection lost, reconnecting…")
		}
		err := c.connect(ctx)
		if ctx.Err() != nil {
			return nil
		}
		var fatal *fatalError
		if errors.As(err, &fatal) {
			return fatal.err
		}
		if err != nil {
			state := StateConnecting
			if !first {
				state = StateReconnecting
			}
			c.setState(state, err.Error()+" Retrying…")
			wait := time.Duration(min(attempt+1, 5)) * 2 * time.Second
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(wait):
			}
			continue
		}
		first = false
		attempt = 0
		if err := c.connected(ctx); err != nil {
			return err
		}
	}
}

type fatalError struct{ err error }

func (f *fatalError) Error() string { return f.err.Error() }

func (c *Client) connect(ctx context.Context) error {
	if c.psk == nil {
		c.setState(c.currentState(), "Preparing encryption keys…")
		c.psk = proto.DerivePSK(c.cfg.Network, c.cfg.Password)
	}
	c.mu.Lock()
	exclude := c.addr
	c.mu.Unlock()
	port := c.conn.LocalAddr().(*net.UDPAddr).Port

	// 1. Work out where the server is.
	var cands []netip.AddrPort
	var rv *rendezvous.Client
	var knock rendezvous.Message
	if c.cfg.Server != "" {
		c.setState(c.currentState(), "Looking up "+c.cfg.Server+"…")
		server, err := resolve(c.cfg.Server)
		if err != nil {
			return err
		}
		cands = []netip.AddrPort{server}
	} else {
		c.setState(c.currentState(), "Looking for the host of network "+strconv.Quote(c.cfg.Network)+"…")
		rv = rendezvous.New(c.cfg.Rendezvous, c.psk)
		host, err := rv.Latest(ctx, rendezvous.RoleHost, 30*time.Minute)
		if errors.Is(err, rendezvous.ErrNotFound) {
			return fmt.Errorf("nobody is hosting network %q right now, or the network name or password is different. Ask the host to start hosting first.", c.cfg.Network)
		}
		if err != nil {
			return err
		}
		cands = netutil.ParseEndpoints(host.Endpoints, 8)
		if len(cands) == 0 {
			return errors.New("the host announced no usable address.")
		}
		eps := netutil.LocalEndpoints(port, exclude)
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		me, err := c.prober.Discover(dctx, c.sendTo, c.cfg.STUNServers)
		cancel()
		if err == nil {
			eps = append([]string{me.Public.String()}, eps...)
			c.mu.Lock()
			c.public = me.Public.String()
			c.mu.Unlock()
		} else {
			c.cfg.Logf("client: cannot determine public address: %v", err)
		}
		knock = rendezvous.Message{Role: rendezvous.RoleKnock, Endpoints: eps}
	}

	// 2. Handshake.
	where := cands[0].String()
	if rv != nil {
		where = "the host"
	}
	c.setState(c.currentState(), "Contacting "+where+"…")
	eph, err := proto.NewEphemeral()
	if err != nil {
		return err
	}
	hs := &handshake{eph: eph, cands: cands, result: make(chan handshakeResult, 1)}
	c.mu.Lock()
	c.hs = hs
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.hs = nil
		c.mu.Unlock()
	}()
	hello := proto.BuildHello(c.psk, eph)
	attempts := handshakeAttempts
	if rv != nil {
		attempts = punchAttempts
	}
	var res handshakeResult
	got := false
	for i := 0; i < attempts && !got; i++ {
		if rv != nil && i%4 == 0 {
			// Ask the host to punch towards us; repeated in case it missed it.
			go func() {
				if err := rv.Publish(ctx, knock); err != nil && ctx.Err() == nil {
					c.cfg.Logf("client: knock: %v", err)
				}
			}()
		}
		for _, to := range cands {
			if _, err := c.conn.WriteToUDPAddrPort(hello, to); err != nil && len(cands) == 1 {
				return fmt.Errorf("cannot reach %s: %v.", to, err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case res = <-hs.result:
			got = true
		case <-time.After(handshakeRetryWait):
		}
	}
	if !got {
		if rv != nil {
			return errors.New("found the host but could not get through. One of the routers blocks direct connections; if this keeps happening, let another friend host or use a VPS server.")
		}
		return fmt.Errorf("no answer from server %s. Check the server address, that the network name and password are exactly right, and that the host is online. You can also leave the server address empty to find the host automatically.", cands[0])
	}
	c.mu.Lock()
	c.server = res.from
	c.mu.Unlock()
	sealer, err := proto.NewSealer(res.keys.ClientToServer, proto.TypeTransport, res.sid, 0)
	if err != nil {
		return err
	}
	opener, err := proto.NewOpener(res.keys.ServerToClient, 0)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.sid, c.sealer, c.opener = res.sid, sealer, opener
	c.lastRecv = time.Now()
	c.peers = map[uint32]*peer{}
	c.peersByIP = map[netip.Addr]*peer{}
	c.peersVersion = 0
	c.mu.Unlock()
	drain(c.lostCh)
	drainCfg(c.configCh)

	// 2. Join the network.
	c.setState(c.currentState(), "Joining network…")
	join := &proto.Control{
		Type:      proto.MsgJoin,
		ClientID:  c.cfg.ClientID,
		Name:      c.cfg.Name,
		LocalAddr: netutil.LocalEndpoints(port, exclude),
		AppVer:    c.cfg.AppVersion,
	}
	var cfg *proto.Control
	for i := 0; i < handshakeAttempts && cfg == nil; i++ {
		c.sendServer(proto.KindControl, join.Marshal())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-c.fatalCh:
			return &fatalError{err}
		case cfg = <-c.configCh:
		case <-time.After(handshakeRetryWait):
		}
	}
	if cfg == nil {
		return errors.New("the server did not accept the join request.")
	}
	ip, err := netip.ParseAddr(cfg.IP)
	if err != nil || !ip.Is4() || cfg.Prefix < 8 || cfg.Prefix > 30 {
		return errors.New("server sent an invalid address")
	}
	addr := netip.PrefixFrom(ip, cfg.Prefix)

	// 3. Bring up the virtual adapter (or keep the existing one).
	c.mu.Lock()
	dev, old := c.dev, c.addr
	c.public = cfg.Public
	c.mu.Unlock()
	if dev == nil || old != addr {
		if dev != nil {
			dev.Close()
		}
		c.setState(c.currentState(), "Creating virtual network adapter…")
		dev, err = c.cfg.OpenDevice(addr)
		if err != nil {
			return &fatalError{err}
		}
		c.mu.Lock()
		c.dev, c.addr = dev, addr
		c.mu.Unlock()
		go c.tunLoop(dev)
	}
	c.setState(StateConnected, "Connected as "+addr.Addr().String())
	return nil
}

func (c *Client) currentState() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == StateConnected || c.state == StateReconnecting {
		return StateReconnecting
	}
	return StateConnecting
}

func drain(ch chan struct{}) {
	select {
	case <-ch:
	default:
	}
}

func drainCfg(ch chan *proto.Control) {
	select {
	case <-ch:
	default:
	}
}

// connected runs timers while the session is up. It returns nil when the
// session is lost (to reconnect) or the context is cancelled.
func (c *Client) connected(ctx context.Context) error {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var lastPing, lastKeep time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-c.fatalCh:
			return err
		case <-c.lostCh:
			return nil
		case now := <-t.C:
			c.mu.Lock()
			silent := now.Sub(c.lastRecv)
			c.mu.Unlock()
			if silent > serverTimeout {
				return nil
			}
			if now.Sub(lastPing) >= pingInterval {
				lastPing = now
				c.sendServer(proto.KindPing, timestamp(now))
			}
			if now.Sub(lastKeep) >= keepInterval {
				lastKeep = now
				c.sendServer(proto.KindControl, (&proto.Control{Type: proto.MsgKeep}).Marshal())
			}
			c.punch(now)
		}
	}
}

// punch keeps direct connections alive and tries to open new ones by sending
// pings to every known address of each peer (UDP hole punching).
func (c *Client) punch(now time.Time) {
	if c.cfg.RelayOnly {
		return
	}
	type out struct {
		to  netip.AddrPort
		pkt []byte
	}
	var sends []out
	c.mu.Lock()
	for _, p := range c.peers {
		if p.directAlive(now) {
			if now.Sub(p.lastPing) >= pingInterval {
				p.lastPing = now
				sends = append(sends, out{p.direct, p.sealer.Seal(proto.KindPing, timestamp(now))})
			}
			continue
		}
		if now.Sub(p.lastPing) >= punchInterval {
			p.lastPing = now
			for _, ep := range p.candidates {
				sends = append(sends, out{ep, p.sealer.Seal(proto.KindPing, timestamp(now))})
			}
		}
	}
	c.mu.Unlock()
	for _, s := range sends {
		_, _ = c.conn.WriteToUDPAddrPort(s.pkt, s.to)
	}
}

func timestamp(t time.Time) []byte {
	return binary.BigEndian.AppendUint64(nil, uint64(t.UnixNano()))
}

func since(b []byte) (time.Duration, bool) {
	if len(b) != 8 {
		return 0, false
	}
	d := time.Since(time.Unix(0, int64(binary.BigEndian.Uint64(b))))
	if d < 0 || d > time.Minute {
		return 0, false
	}
	return d, true
}

func (c *Client) sendTo(p []byte, to netip.AddrPort) error {
	_, err := c.conn.WriteToUDPAddrPort(p, to)
	return err
}

func (c *Client) sendServer(kind byte, payload []byte) {
	c.mu.Lock()
	sealer, server := c.sealer, c.server
	c.mu.Unlock()
	if sealer == nil {
		return
	}
	_, _ = c.conn.WriteToUDPAddrPort(sealer.Seal(kind, payload), server)
}

// tunLoop forwards packets written by Windows to the virtual adapter.
func (c *Client) tunLoop(dev tunnel.Device) {
	buf := make([]byte, 65535)
	for {
		n, err := dev.ReadPacket(buf)
		if err != nil {
			c.mu.Lock()
			current := c.dev == dev
			c.mu.Unlock()
			if current {
				c.cfg.Logf("client: adapter read: %v", err)
			}
			return
		}
		c.sendIP(buf[:n])
	}
}

func (c *Client) sendIP(pkt []byte) {
	dst, ok := proto.IPv4Dst(pkt)
	if !ok {
		return // IPv6 and garbage are not carried
	}
	now := time.Now()
	c.mu.Lock()
	sealer, server, subnet := c.sealer, c.server, c.addr.Masked()
	var to netip.AddrPort
	var data []byte
	if p := c.peersByIP[dst]; p != nil && p.directAlive(now) {
		to, data = p.direct, p.sealer.Seal(proto.KindIP, pkt)
	}
	c.mu.Unlock()
	if data == nil {
		bcast := proto.IsBroadcastLike(dst, subnet)
		if sealer == nil || !(subnet.Contains(dst) || bcast) {
			return
		}
		if bcast && !proto.IsSystemChatter(pkt) {
			c.bcastOut.Add(1)
		}
		to, data = server, sealer.Seal(proto.KindIP, pkt)
	}
	_, _ = c.conn.WriteToUDPAddrPort(data, to)
}

// readLoop handles every datagram arriving on the UDP socket.
func (c *Client) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, from, err := c.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if s := err.Error(); strings.Contains(s, "forcibly closed") || strings.Contains(s, "refused") {
				continue // ICMP port unreachable from an earlier send (Windows)
			}
			c.cfg.Logf("client: udp read: %v", err)
			return
		}
		if n == 0 {
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		p := buf[:n]
		if stun.IsMessage(p) {
			c.prober.Handle(p)
			continue
		}
		switch p[0] {
		case proto.TypeWelcome:
			c.handleWelcome(p, from)
		case proto.TypeTransport:
			c.handleTransport(p, from)
		case proto.TypeReset:
			c.handleReset(p, from)
		case proto.TypePeer:
			c.handlePeer(p, from)
		}
	}
}

func (c *Client) handleWelcome(p []byte, from netip.AddrPort) {
	c.mu.Lock()
	hs := c.hs
	c.mu.Unlock()
	if hs == nil || !slices.Contains(hs.cands, from) {
		return
	}
	sid, keys, err := proto.ClientFinish(c.psk, hs.eph, p)
	if err != nil {
		return
	}
	select {
	case hs.result <- handshakeResult{sid, keys, from}:
	default:
	}
}

func (c *Client) handleReset(p []byte, from netip.AddrPort) {
	if len(p) != proto.ResetLen {
		return
	}
	c.mu.Lock()
	match := from == c.server && c.sealer != nil && binary.BigEndian.Uint32(p[1:]) == c.sid
	c.mu.Unlock()
	if match {
		// The server restarted or forgot us. Reconnect.
		select {
		case c.lostCh <- struct{}{}:
		default:
		}
	}
}

func (c *Client) handleTransport(p []byte, from netip.AddrPort) {
	c.mu.Lock()
	opener, server := c.opener, c.server
	c.mu.Unlock()
	if opener == nil || from != server {
		return
	}
	kind, payload, err := opener.Open(p)
	if err != nil {
		return
	}
	c.mu.Lock()
	if c.opener != opener {
		c.mu.Unlock()
		return
	}
	c.lastRecv = time.Now()
	c.mu.Unlock()
	switch kind {
	case proto.KindIP:
		c.deliver(payload, netip.Addr{})
	case proto.KindPong:
		if d, ok := since(payload); ok {
			c.mu.Lock()
			c.serverRTT = d
			c.mu.Unlock()
		}
	case proto.KindControl:
		msg, err := proto.ParseControl(payload)
		if err == nil {
			c.handleControl(msg)
		}
	}
}

func (c *Client) handleControl(m *proto.Control) {
	switch m.Type {
	case proto.MsgConfig:
		select {
		case c.configCh <- m:
		default:
		}
	case proto.MsgPeers:
		c.updatePeers(m)
	case proto.MsgKeepAck:
		c.mu.Lock()
		stale := m.PeersVersion != c.peersVersion
		c.mu.Unlock()
		if stale {
			c.sendServer(proto.KindControl, (&proto.Control{Type: proto.MsgGetPeers}).Marshal())
		}
	case proto.MsgError:
		select {
		case c.fatalCh <- fmt.Errorf("server refused: %s", m.Error):
		default:
		}
	}
}

func (c *Client) updatePeers(m *proto.Control) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if m.PeersVersion < c.peersVersion {
		return // an older list arriving late
	}
	c.peersVersion = m.PeersVersion
	peers := map[uint32]*peer{}
	byIP := map[netip.Addr]*peer{}
	for _, info := range m.Peers {
		ip, err := netip.ParseAddr(info.IP)
		if err != nil || len(info.PairKey) != 32 || info.SessionID == c.sid {
			continue
		}
		var cands []netip.AddrPort
		for _, e := range info.Endpoints {
			// Loopback shows up when the peer runs on the server's machine.
			if ap, err := netip.ParseAddrPort(e); err == nil && ap.Addr().Is4() && !ap.Addr().IsLoopback() && !c.addr.Contains(ap.Addr()) {
				cands = append(cands, ap)
			}
		}
		p := c.peers[info.SessionID]
		if p != nil && string(p.info.PairKey) == string(info.PairKey) {
			p.info = info
			p.candidates = cands
		} else {
			sealer, err1 := proto.NewSealer(info.PairKey, proto.TypePeer, c.sid, c.sid)
			opener, err2 := proto.NewOpener(info.PairKey, info.SessionID)
			if err1 != nil || err2 != nil {
				continue
			}
			p = &peer{info: info, ip: ip, sealer: sealer, opener: opener, candidates: cands}
		}
		peers[info.SessionID] = p
		byIP[ip] = p
	}
	c.peers, c.peersByIP = peers, byIP
}

func (c *Client) handlePeer(p []byte, from netip.AddrPort) {
	sid, ok := proto.HeaderID(p)
	if !ok {
		return
	}
	c.mu.Lock()
	pr := c.peers[sid]
	c.mu.Unlock()
	if pr == nil {
		return
	}
	kind, payload, err := pr.opener.Open(p)
	if err != nil {
		return
	}
	switch kind {
	case proto.KindPing:
		_, _ = c.conn.WriteToUDPAddrPort(pr.sealer.Seal(proto.KindPong, payload), from)
	case proto.KindPong:
		if d, ok := since(payload); ok {
			c.mu.Lock()
			// Prefer the first working address; switch only if it went quiet.
			if !pr.directAlive(time.Now()) || pr.direct == from {
				pr.direct = from
				pr.lastPong = time.Now()
				pr.rtt = d
			}
			c.mu.Unlock()
		}
	case proto.KindIP:
		c.deliver(payload, pr.ip)
	}
}

// deliver hands an incoming packet to Windows. If wantSrc is valid the packet
// must come from that address (peer traffic cannot be spoofed).
func (c *Client) deliver(pkt []byte, wantSrc netip.Addr) {
	src, ok := proto.IPv4Src(pkt)
	if !ok {
		return
	}
	dst, _ := proto.IPv4Dst(pkt)
	c.mu.Lock()
	dev, addr := c.dev, c.addr
	c.mu.Unlock()
	if dev == nil || !addr.Contains(src) || (wantSrc.IsValid() && src != wantSrc) {
		return
	}
	if dst != addr.Addr() {
		if !proto.IsBroadcastLike(dst, addr.Masked()) {
			return
		}
		if !proto.IsSystemChatter(pkt) {
			c.bcastIn.Add(1)
		}
	}
	_ = dev.WritePacket(pkt)
}

func resolve(server string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid server address %q (use host:port).", server)
	}
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, port))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("cannot find server %q: %v.", host, err)
	}
	ap := addr.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}
