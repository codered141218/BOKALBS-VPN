package proto

import (
	"encoding/binary"
	"net/netip"
)

// IPv4 header helpers. Only IPv4 is carried by the VPN.

// IPv4Dst returns the destination of an IPv4 packet.
func IPv4Dst(p []byte) (netip.Addr, bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(p[16:20])), true
}

// IPv4Src returns the source of an IPv4 packet.
func IPv4Src(p []byte) (netip.Addr, bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(p[12:16])), true
}

// IsBroadcastLike reports whether dst must be delivered to every member of
// the network: limited broadcast, the subnet broadcast address or multicast.
// LAN games such as Warcraft III find each other this way.
func IsBroadcastLike(dst netip.Addr, subnet netip.Prefix) bool {
	if !dst.Is4() {
		return false
	}
	if dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || dst.IsMulticast() {
		return true
	}
	return subnet.IsValid() && dst == LastAddr(subnet)
}

// LastAddr returns the broadcast address of an IPv4 prefix.
func LastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	v := binary.BigEndian.Uint32(a[:]) | (^uint32(0) >> p.Bits())
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], v)
	return netip.AddrFrom4(out)
}

// IsSystemChatter reports whether p is background broadcast traffic Windows
// sends by itself (name lookups, network discovery, IGMP), as opposed to
// broadcasts from applications such as LAN games.
func IsSystemChatter(p []byte) bool {
	if len(p) < 20 || p[0]>>4 != 4 {
		return false
	}
	ihl := int(p[0]&0x0f) * 4
	if p[9] != 17 { // not UDP: IGMP and friends
		return true
	}
	if len(p) < ihl+4 {
		return true
	}
	switch binary.BigEndian.Uint16(p[ihl+2 : ihl+4]) {
	case 67, 68, 137, 138, 1900, 3702, 5353, 5355:
		return true
	}
	return false
}
