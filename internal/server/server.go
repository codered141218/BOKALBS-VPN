// Package server implements the BOKALBS VPN coordination server.
//
// The server is the meeting point of a network: clients authenticate with
// the network password, get a stable virtual IP address, learn about each
// other (so they can connect directly, peer to peer) and, when a direct
// connection is impossible, relay their traffic through the server.
// It also fans out broadcast packets so LAN games can discover each other.
//
// The server does not need a virtual network adapter or administrator rights.
package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/proto"
)

const (
	DefaultPort   = 47820
	DefaultSubnet = "10.77.0.0/24"

	sessionTimeout = 45 * time.Second
	pendingTimeout = 15 * time.Second
	maxNameLen     = 32
	maxPacket      = 65535
)

// Config configures a server.
type Config struct {
	Listen    string       // UDP address to listen on, e.g. ":47820"
	Network   string       // network name
	Password  string       // network password
	Subnet    netip.Prefix // virtual network, defaults to 10.77.0.0/24
	LeaseFile string       // optional file remembering which device got which IP
	Logf      func(format string, args ...any)
}

type session struct {
	id       uint32
	addr     netip.AddrPort
	sealer   *proto.Sealer
	opener   *proto.Opener
	created  time.Time
	lastSeen time.Time

	joined   bool
	clientID string
	name     string
	ip       netip.Addr
	local    []string
}

// Server is a running coordination server.
type Server struct {
	cfg        Config
	psk        []byte
	pairSecret []byte
	conn       *net.UDPConn

	mu           sync.Mutex
	sessions     map[uint32]*session
	byIP         map[netip.Addr]*session
	leases       map[string]netip.Addr
	peersVersion uint64
}

// New validates the configuration and derives the network key.
func New(cfg Config) (*Server, error) {
	if cfg.Network == "" || cfg.Password == "" {
		return nil, errors.New("network name and password are required")
	}
	if !cfg.Subnet.IsValid() {
		cfg.Subnet = netip.MustParsePrefix(DefaultSubnet)
	}
	if !cfg.Subnet.Addr().Is4() || cfg.Subnet.Bits() < 16 || cfg.Subnet.Bits() > 29 {
		return nil, errors.New("subnet must be an IPv4 prefix between /16 and /29")
	}
	cfg.Subnet = cfg.Subnet.Masked()
	if cfg.Listen == "" {
		cfg.Listen = ":" + strconv.Itoa(DefaultPort)
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	s := &Server{
		cfg:        cfg,
		psk:        proto.DerivePSK(cfg.Network, cfg.Password),
		pairSecret: secret,
		sessions:   map[uint32]*session{},
		byIP:       map[netip.Addr]*session{},
		leases:     map[string]netip.Addr{},
	}
	s.loadLeases()
	return s, nil
}

// Listen opens the UDP socket. It is separate from Run so callers can report
// "port already in use" errors before starting the server in the background.
func (s *Server) Listen() error {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.Listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("cannot listen on UDP %s: %w", s.cfg.Listen, err)
	}
	_ = conn.SetReadBuffer(4 << 20)
	_ = conn.SetWriteBuffer(4 << 20)
	s.conn = conn
	return nil
}

// Addr returns the local address of the server socket (after Listen).
func (s *Server) Addr() net.Addr { return s.conn.LocalAddr() }

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if s.conn == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	s.cfg.Logf("server: network %q on %s, subnet %s", s.cfg.Network, s.conn.LocalAddr(), s.cfg.Subnet)
	go func() {
		<-ctx.Done()
		s.conn.Close()
	}()
	go s.housekeeping(ctx)

	buf := make([]byte, maxPacket)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			// On Windows an ICMP "port unreachable" from a previous send is
			// reported on the next read; it is harmless.
			if isConnReset(err) {
				continue
			}
			return err
		}
		s.handle(buf[:n], unmap(from))
	}
}

func unmap(a netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}

func isConnReset(err error) bool {
	return strings.Contains(err.Error(), "forcibly closed") || strings.Contains(err.Error(), "connection reset") ||
		strings.Contains(err.Error(), "connection refused")
}

func (s *Server) send(addr netip.AddrPort, p []byte) {
	_, _ = s.conn.WriteToUDPAddrPort(p, addr)
}

func (s *Server) handle(p []byte, from netip.AddrPort) {
	if len(p) == 0 {
		return
	}
	switch p[0] {
	case proto.TypeHello:
		s.handleHello(p, from)
	case proto.TypeTransport:
		s.handleTransport(p, from)
	}
}

func (s *Server) handleHello(p []byte, from netip.AddrPort) {
	clientPub, err := proto.ParseHello(s.psk, p)
	if err != nil {
		// Wrong password, a scanner or an incompatible version: stay silent.
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := 0
	for _, ss := range s.sessions {
		if !ss.joined {
			pending++
		}
	}
	if pending > 256 {
		return
	}
	id := proto.RandomID()
	for s.sessions[id] != nil {
		id = proto.RandomID()
	}
	welcome, keys, err := proto.ServerHandshake(s.psk, clientPub, id)
	if err != nil {
		return
	}
	sealer, err := proto.NewSealer(keys.ServerToClient, proto.TypeTransport, id, 0)
	if err != nil {
		return
	}
	opener, err := proto.NewOpener(keys.ClientToServer, 0)
	if err != nil {
		return
	}
	now := time.Now()
	s.sessions[id] = &session{id: id, addr: from, sealer: sealer, opener: opener, created: now, lastSeen: now}
	s.send(from, welcome)
}

func (s *Server) handleTransport(p []byte, from netip.AddrPort) {
	id, ok := proto.HeaderID(p)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ss := s.sessions[id]
	if ss == nil {
		s.send(from, proto.BuildReset(id))
		return
	}
	kind, payload, err := ss.opener.Open(p)
	if err != nil {
		return
	}
	ss.lastSeen = time.Now()
	if ss.addr != from {
		// The client's NAT mapping changed (roaming); follow it.
		ss.addr = from
		if ss.joined {
			s.peersChangedLocked()
		}
	}
	switch kind {
	case proto.KindControl:
		c, err := proto.ParseControl(payload)
		if err != nil {
			return
		}
		s.handleControlLocked(ss, c)
	case proto.KindIP:
		s.routeLocked(ss, payload)
	case proto.KindPing:
		s.send(ss.addr, ss.sealer.Seal(proto.KindPong, payload))
	}
}

func (s *Server) sendControlLocked(ss *session, c *proto.Control) {
	s.send(ss.addr, ss.sealer.Seal(proto.KindControl, c.Marshal()))
}

func (s *Server) handleControlLocked(ss *session, c *proto.Control) {
	switch c.Type {
	case proto.MsgJoin:
		if !ss.joined {
			if err := s.joinLocked(ss, c); err != nil {
				s.sendControlLocked(ss, &proto.Control{Type: proto.MsgError, Error: err.Error()})
				return
			}
		}
		s.sendControlLocked(ss, &proto.Control{
			Type:   proto.MsgConfig,
			IP:     ss.ip.String(),
			Prefix: s.cfg.Subnet.Bits(),
			Public: ss.addr.String(),
		})
		s.sendPeersLocked(ss)
	case proto.MsgGetPeers:
		if ss.joined {
			s.sendPeersLocked(ss)
		}
	case proto.MsgKeep:
		s.sendControlLocked(ss, &proto.Control{Type: proto.MsgKeepAck, PeersVersion: s.peersVersion})
	case proto.MsgBye:
		s.removeLocked(ss)
		s.peersChangedLocked()
	}
}

func (s *Server) joinLocked(ss *session, c *proto.Control) error {
	if c.ClientID == "" || len(c.ClientID) > 64 {
		return errors.New("invalid client id")
	}
	// A device reconnecting replaces its previous session.
	for _, other := range s.sessions {
		if other != ss && other.joined && other.clientID == c.ClientID {
			s.removeLocked(other)
		}
	}
	ip, ok := s.leases[c.ClientID]
	if !ok || !s.cfg.Subnet.Contains(ip) || s.byIP[ip] != nil {
		ip, ok = s.allocateLocked(c.ClientID)
		if !ok {
			return errors.New("network is full")
		}
		s.leases[c.ClientID] = ip
		s.saveLeasesLocked()
	}
	name := strings.TrimSpace(c.Name)
	if len(name) > maxNameLen {
		name = name[:maxNameLen]
	}
	if name == "" {
		name = "player-" + ip.String()
	}
	ss.joined = true
	ss.clientID = c.ClientID
	ss.name = name
	ss.ip = ip
	ss.local = sanitizeEndpoints(c.LocalAddr)
	s.byIP[ip] = ss
	s.cfg.Logf("server: %q joined as %s from %s", name, ip, ss.addr)
	s.peersChangedLocked()
	return nil
}

func sanitizeEndpoints(in []string) []string {
	var out []string
	for _, e := range in {
		if ap, err := netip.ParseAddrPort(e); err == nil && ap.Addr().Is4() && len(out) < 8 {
			out = append(out, ap.String())
		}
	}
	return out
}

// allocateLocked picks the lowest free address that is not leased to another
// device. When every address has been leased once, it reuses one whose owner
// is offline.
func (s *Server) allocateLocked(clientID string) (netip.Addr, bool) {
	leased := map[netip.Addr]bool{}
	for id, ip := range s.leases {
		if id != clientID {
			leased[ip] = true
		}
	}
	first := s.cfg.Subnet.Addr().Next().Next() // .1 is reserved
	last := proto.LastAddr(s.cfg.Subnet)
	for pass := 0; pass < 2; pass++ {
		for ip := first; ip.IsValid() && ip.Less(last); ip = ip.Next() {
			if s.byIP[ip] != nil || (pass == 0 && leased[ip]) {
				continue
			}
			if pass == 1 {
				for id, lip := range s.leases {
					if lip == ip {
						delete(s.leases, id)
					}
				}
			}
			return ip, true
		}
	}
	return netip.Addr{}, false
}

func (s *Server) removeLocked(ss *session) {
	delete(s.sessions, ss.id)
	if ss.joined && s.byIP[ss.ip] == ss {
		delete(s.byIP, ss.ip)
		s.cfg.Logf("server: %q (%s) left", ss.name, ss.ip)
	}
}

func (s *Server) peersChangedLocked() {
	s.peersVersion++
	for _, ss := range s.sessions {
		if ss.joined {
			s.sendPeersLocked(ss)
		}
	}
}

func (s *Server) sendPeersLocked(to *session) {
	peers := make([]proto.PeerInfo, 0, len(s.byIP))
	for _, ss := range s.byIP {
		if ss == to {
			continue
		}
		eps := append([]string{ss.addr.String()}, ss.local...)
		peers = append(peers, proto.PeerInfo{
			SessionID: ss.id,
			ClientID:  ss.clientID,
			Name:      ss.name,
			IP:        ss.ip.String(),
			Endpoints: eps,
			PairKey:   proto.PairKey(s.pairSecret, strconv.FormatUint(uint64(ss.id), 10), strconv.FormatUint(uint64(to.id), 10)),
		})
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].IP < peers[j].IP })
	s.sendControlLocked(to, &proto.Control{Type: proto.MsgPeers, PeersVersion: s.peersVersion, Peers: peers})
}

// routeLocked relays an IP packet from one member to another, or to everyone
// for broadcasts.
func (s *Server) routeLocked(from *session, pkt []byte) {
	if !from.joined {
		return
	}
	src, ok := proto.IPv4Src(pkt)
	if !ok || src != from.ip {
		return // only IPv4, and no spoofing of other members' addresses
	}
	dst, _ := proto.IPv4Dst(pkt)
	if proto.IsBroadcastLike(dst, s.cfg.Subnet) {
		for _, ss := range s.byIP {
			if ss != from {
				s.send(ss.addr, ss.sealer.Seal(proto.KindIP, pkt))
			}
		}
		return
	}
	if to := s.byIP[dst]; to != nil {
		s.send(to.addr, to.sealer.Seal(proto.KindIP, pkt))
	}
}

func (s *Server) housekeeping(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			changed := false
			for _, ss := range s.sessions {
				if ss.joined && now.Sub(ss.lastSeen) > sessionTimeout {
					s.removeLocked(ss)
					changed = true
				} else if !ss.joined && now.Sub(ss.created) > pendingTimeout {
					s.removeLocked(ss)
				}
			}
			if changed {
				s.peersChangedLocked()
			}
			s.mu.Unlock()
		}
	}
}

// Member is a summary of a connected device, for status displays.
type Member struct {
	Name     string `json:"name"`
	IP       string `json:"ip"`
	Endpoint string `json:"endpoint"`
}

// Members lists the devices currently on the network.
func (s *Server) Members() []Member {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Member, 0, len(s.byIP))
	for _, ss := range s.byIP {
		out = append(out, Member{Name: ss.name, IP: ss.ip.String(), Endpoint: ss.addr.String()})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := netip.MustParseAddr(out[i].IP), netip.MustParseAddr(out[j].IP)
		return a.Less(b)
	})
	return out
}

func (s *Server) loadLeases() {
	if s.cfg.LeaseFile == "" {
		return
	}
	b, err := os.ReadFile(s.cfg.LeaseFile)
	if err != nil {
		return
	}
	var m map[string]string
	if json.Unmarshal(b, &m) != nil {
		return
	}
	for id, ipStr := range m {
		if ip, err := netip.ParseAddr(ipStr); err == nil && s.cfg.Subnet.Contains(ip) {
			s.leases[id] = ip
		}
	}
}

func (s *Server) saveLeasesLocked() {
	if s.cfg.LeaseFile == "" {
		return
	}
	m := map[string]string{}
	for id, ip := range s.leases {
		m[id] = ip.String()
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	tmp := s.cfg.LeaseFile + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, s.cfg.LeaseFile)
	}
}
