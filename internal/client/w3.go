package client

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strconv"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/proto"
)

// Warcraft III LAN helper.
//
// Warcraft III (1.2x) finds LAN games by broadcasting a "search game" packet
// to 255.255.255.255:6112; a hosting game answers the searcher directly with
// a "game info" packet. Windows does not reliably send those broadcasts into
// a VPN adapter, so the helper sends the search itself, unicast, to every
// member's port 6112, as if it came from this PC's game. The host's game
// answers this PC's port 6112, and the game here lists the game. Unicast
// traffic always works through the VPN, so this does not depend on how
// Windows routes broadcasts.

const (
	w3Port         = 6112
	w3Header       = 0xF7
	w3SearchGame   = 0x2F
	w3GameInfo     = 0x30
	w3SearchPeriod = 3 * time.Second
	gameSeenFor    = 15 * time.Second
)

var (
	w3Products = [][4]byte{
		{'P', 'X', '3', 'W'}, // The Frozen Throne ("W3XP" little endian)
		{'3', 'R', 'A', 'W'}, // Reign of Chaos ("WAR3")
	}
	w3Versions = []uint32{26, 27, 28, 24, 25, 29, 30, 31, 23, 22, 21, 20}
)

// w3Searches are the payloads of "search game" packets for every product and
// version; a game only answers searches for its own version.
var w3Searches = func() [][]byte {
	var out [][]byte
	for _, prod := range w3Products {
		for _, ver := range w3Versions {
			p := make([]byte, 16)
			p[0], p[1] = w3Header, w3SearchGame
			binary.LittleEndian.PutUint16(p[2:4], 16)
			copy(p[4:8], prod[:])
			binary.LittleEndian.PutUint32(p[8:12], ver)
			out = append(out, p)
		}
	}
	return out
}()

// GameSeen is a LAN game announced by another member.
type GameSeen struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	Version string `json:"version"`
}

type gameSeen struct {
	GameSeen
	at time.Time
}

// searchW3Games asks every member's Warcraft III for its games.
func (c *Client) searchW3Games() {
	c.mu.Lock()
	me := c.addr.Addr()
	peers := make([]netip.Addr, 0, len(c.peers))
	for _, p := range c.peers {
		peers = append(peers, p.ip)
	}
	c.mu.Unlock()
	if !me.IsValid() {
		return
	}
	for _, ip := range peers {
		for _, s := range w3Searches {
			c.sendIP(udpIPv4(me, ip, w3Port, w3Port, s))
		}
	}
}

// noteW3Game records a "game info" packet delivered to this PC.
func (c *Client) noteW3Game(pkt []byte) {
	payload, _, dport, ok := udpPayload(pkt)
	if !ok || dport != w3Port || len(payload) < 21 || payload[0] != w3Header || payload[1] != w3GameInfo {
		return
	}
	src, _ := proto.IPv4Src(pkt)
	name := payload[20:]
	if i := bytes.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	if len(name) > 64 {
		name = name[:64]
	}
	prod := "TFT"
	if string(payload[4:8]) == "3RAW" {
		prod = "RoC"
	}
	g := GameSeen{
		Name:    string(name),
		Host:    src.String(),
		Version: prod + " 1." + strconv.FormatUint(uint64(binary.LittleEndian.Uint32(payload[8:12])), 10),
	}
	c.mu.Lock()
	if c.games == nil {
		c.games = map[string]*gameSeen{}
	}
	c.games[g.Host+"\x00"+g.Name] = &gameSeen{GameSeen: g, at: time.Now()}
	c.mu.Unlock()
}

// udpIPv4 builds an IPv4/UDP packet with valid checksums.
func udpIPv4(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64 // TTL
	p[9] = 17 // UDP
	s, d := src.As4(), dst.As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20], 0))

	u := p[20:]
	binary.BigEndian.PutUint16(u[0:2], sport)
	binary.BigEndian.PutUint16(u[2:4], dport)
	binary.BigEndian.PutUint16(u[4:6], uint16(8+len(payload)))
	copy(u[8:], payload)
	// Pseudo header: src, dst, zero, protocol, UDP length.
	var sum uint32
	for i := 0; i < 4; i += 2 {
		sum += uint32(s[i])<<8 | uint32(s[i+1])
		sum += uint32(d[i])<<8 | uint32(d[i+1])
	}
	sum += 17 + uint32(len(u))
	cs := checksum(u, sum)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:8], cs)
	return p
}

func checksum(b []byte, sum uint32) uint16 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// udpPayload returns the payload and ports of an IPv4/UDP packet.
func udpPayload(p []byte) ([]byte, uint16, uint16, bool) {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 17 {
		return nil, 0, 0, false
	}
	ihl := int(p[0]&0x0f) * 4
	if len(p) < ihl+8 {
		return nil, 0, 0, false
	}
	u := p[ihl:]
	return u[8:], binary.BigEndian.Uint16(u[0:2]), binary.BigEndian.Uint16(u[2:4]), true
}
