// Package stun asks public STUN servers which internet address and port a
// UDP socket appears from. Hosts and players behind home routers use this to
// connect to each other without port forwarding (UDP hole punching).
package stun

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultServers are public STUN servers.
var DefaultServers = []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478", "stun1.l.google.com:19302"}

const (
	magicCookie     = 0x2112A442
	bindingRequest  = 0x0001
	bindingSuccess  = 0x0101
	attrMapped      = 0x0001
	attrXorMapped   = 0x0020
	headerLen       = 20
	familyIPv4      = 0x01
	attrHeaderLen   = 4
	requestAttempts = 3
)

// IsMessage reports whether p looks like a STUN message, so it can be told
// apart from VPN packets arriving on the same socket.
func IsMessage(p []byte) bool {
	return len(p) >= headerLen && p[0]&0xC0 == 0 &&
		binary.BigEndian.Uint32(p[4:8]) == magicCookie &&
		int(binary.BigEndian.Uint16(p[2:4]))+headerLen == len(p)
}

func request() ([12]byte, []byte) {
	var tx [12]byte
	_, _ = rand.Read(tx[:])
	p := make([]byte, headerLen)
	binary.BigEndian.PutUint16(p[0:2], bindingRequest)
	binary.BigEndian.PutUint32(p[4:8], magicCookie)
	copy(p[8:20], tx[:])
	return tx, p
}

// parseResponse returns the transaction id and mapped address of a binding
// success response.
func parseResponse(p []byte) ([12]byte, netip.AddrPort, bool) {
	var tx [12]byte
	if !IsMessage(p) || binary.BigEndian.Uint16(p[0:2]) != bindingSuccess {
		return tx, netip.AddrPort{}, false
	}
	copy(tx[:], p[8:20])
	var mapped netip.AddrPort
	attrs := p[headerLen:]
	for len(attrs) >= attrHeaderLen {
		typ := binary.BigEndian.Uint16(attrs[0:2])
		l := int(binary.BigEndian.Uint16(attrs[2:4]))
		if attrHeaderLen+l > len(attrs) {
			break
		}
		v := attrs[attrHeaderLen : attrHeaderLen+l]
		if l >= 8 && v[1] == familyIPv4 {
			port := binary.BigEndian.Uint16(v[2:4])
			var ip [4]byte
			copy(ip[:], v[4:8])
			switch typ {
			case attrXorMapped:
				port ^= magicCookie >> 16
				binary.BigEndian.PutUint32(ip[:], binary.BigEndian.Uint32(ip[:])^magicCookie)
				return tx, netip.AddrPortFrom(netip.AddrFrom4(ip), port), true
			case attrMapped:
				mapped = netip.AddrPortFrom(netip.AddrFrom4(ip), port)
			}
		}
		attrs = attrs[attrHeaderLen+(l+3)&^3:]
	}
	return tx, mapped, mapped.IsValid()
}

// BuildResponse creates a binding success response (used by test servers).
func BuildResponse(req []byte, from netip.AddrPort) []byte {
	p := make([]byte, headerLen+attrHeaderLen+8)
	binary.BigEndian.PutUint16(p[0:2], bindingSuccess)
	binary.BigEndian.PutUint16(p[2:4], attrHeaderLen+8)
	binary.BigEndian.PutUint32(p[4:8], magicCookie)
	copy(p[8:20], req[8:20])
	a := p[headerLen:]
	binary.BigEndian.PutUint16(a[0:2], attrXorMapped)
	binary.BigEndian.PutUint16(a[2:4], 8)
	a[5] = familyIPv4
	binary.BigEndian.PutUint16(a[6:8], from.Port()^(magicCookie>>16))
	ip := from.Addr().As4()
	binary.BigEndian.PutUint32(a[8:12], binary.BigEndian.Uint32(ip[:])^magicCookie)
	return p
}

// IsRequest reports whether p is a binding request (used by test servers).
func IsRequest(p []byte) bool {
	return IsMessage(p) && binary.BigEndian.Uint16(p[0:2]) == bindingRequest
}

// SendFunc sends a datagram from the socket being probed.
type SendFunc func(p []byte, to netip.AddrPort) error

// Prober matches STUN answers, which arrive through the owner's own read
// loop, to the questions it asked.
type Prober struct {
	mu      sync.Mutex
	pending map[[12]byte]chan netip.AddrPort
}

// Handle consumes a STUN packet read from the socket. It returns false if p
// is not a STUN response.
func (pr *Prober) Handle(p []byte) bool {
	tx, mapped, ok := parseResponse(p)
	if !ok {
		return IsMessage(p)
	}
	pr.mu.Lock()
	ch := pr.pending[tx]
	pr.mu.Unlock()
	if ch != nil {
		select {
		case ch <- mapped:
		default:
		}
	}
	return true
}

// Query asks one STUN server for the socket's public address.
func (pr *Prober) Query(ctx context.Context, send SendFunc, server netip.AddrPort) (netip.AddrPort, error) {
	tx, req := request()
	ch := make(chan netip.AddrPort, 1)
	pr.mu.Lock()
	if pr.pending == nil {
		pr.pending = map[[12]byte]chan netip.AddrPort{}
	}
	pr.pending[tx] = ch
	pr.mu.Unlock()
	defer func() {
		pr.mu.Lock()
		delete(pr.pending, tx)
		pr.mu.Unlock()
	}()
	for i := 0; i < requestAttempts; i++ {
		if err := send(req, server); err != nil {
			return netip.AddrPort{}, err
		}
		select {
		case <-ctx.Done():
			return netip.AddrPort{}, ctx.Err()
		case m := <-ch:
			return m, nil
		case <-time.After(700 * time.Millisecond):
		}
	}
	return netip.AddrPort{}, errors.New("no answer from STUN server " + server.String())
}

// Result of probing several STUN servers.
type Result struct {
	Public netip.AddrPort // the address other computers can send to
	// Symmetric is true when the router uses a different public port for
	// every destination; hole punching then usually fails.
	Symmetric bool
	Seen      []netip.AddrPort // every answer, in order
}

// PredictPorts guesses which public ports a symmetric router will use for
// the next connections. Many such routers hand out ports in sequence (or
// in fixed steps), so the next ports follow the last ones seen. It returns
// up to n ports, most likely first.
func (r Result) PredictPorts(n int) []uint16 {
	if len(r.Seen) == 0 {
		return nil
	}
	last := int(r.Seen[len(r.Seen)-1].Port())
	step := 1
	if len(r.Seen) >= 2 {
		if d := last - int(r.Seen[len(r.Seen)-2].Port()); d != 0 && d > -512 && d < 512 {
			step = d
		}
	}
	var out []uint16
	seen := map[int]bool{}
	add := func(p int) {
		if p >= 1024 && p <= 65535 && !seen[p] && len(out) < n {
			seen[p] = true
			out = append(out, uint16(p))
		}
	}
	for k := 1; len(out) < n && k <= n; k++ {
		add(last + step*k)
		if step != 1 {
			add(last + k)
		}
		if step > 0 {
			add(last - k) // some routers count down or reuse recent ports
		}
	}
	return out
}

// Discover asks up to two servers for the socket's public address.
func (pr *Prober) Discover(ctx context.Context, send SendFunc, servers []string) (Result, error) {
	var seen []netip.AddrPort
	var lastErr error
	for _, s := range servers {
		if len(seen) == 2 {
			break
		}
		addr, err := Resolve(s)
		if err != nil {
			lastErr = err
			continue
		}
		qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		m, err := pr.Query(qctx, send, addr)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		seen = append(seen, m)
	}
	if len(seen) == 0 {
		if lastErr == nil {
			lastErr = errors.New("no STUN servers")
		}
		return Result{}, lastErr
	}
	res := Result{Public: seen[0], Seen: seen}
	if len(seen) == 2 && seen[0] != seen[1] {
		res.Symmetric = true
		// The next connection most likely follows the latest mapping.
		res.Public = seen[1]
	}
	return res, nil
}

// Resolve looks up a STUN server's IPv4 address.
func Resolve(server string) (netip.AddrPort, error) {
	a, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ap := a.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// Servers returns the STUN servers to use: BOKALBS_STUN (comma separated)
// when set, otherwise DefaultServers.
func Servers() []string {
	if v := os.Getenv("BOKALBS_STUN"); v != "" {
		return strings.Split(v, ",")
	}
	return DefaultServers
}
