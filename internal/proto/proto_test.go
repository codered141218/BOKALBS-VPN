package proto

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestHandshakeAndTransport(t *testing.T) {
	psk := DerivePSK("lan-party", "secret")
	eph, err := NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	hello := BuildHello(psk, eph)
	cpub, err := ParseHello(psk, hello)
	if err != nil {
		t.Fatal(err)
	}
	welcome, skeys, err := ServerHandshake(psk, cpub, 42)
	if err != nil {
		t.Fatal(err)
	}
	sid, ckeys, err := ClientFinish(psk, eph, welcome)
	if err != nil {
		t.Fatal(err)
	}
	if sid != 42 || !bytes.Equal(ckeys.ClientToServer, skeys.ClientToServer) || !bytes.Equal(ckeys.ServerToClient, skeys.ServerToClient) {
		t.Fatal("keys or session id mismatch")
	}

	s, _ := NewSealer(ckeys.ClientToServer, TypeTransport, sid, 0)
	o, _ := NewOpener(skeys.ClientToServer, 0)
	pkt := s.Seal(KindIP, []byte("hello world"))
	if id, _ := HeaderID(pkt); id != 42 {
		t.Fatalf("header id %d", id)
	}
	kind, payload, err := o.Open(pkt)
	if err != nil || kind != KindIP || string(payload) != "hello world" {
		t.Fatalf("open: %v %d %q", err, kind, payload)
	}
	if _, _, err := o.Open(pkt); err != ErrReplay {
		t.Fatalf("replay accepted: %v", err)
	}
	pkt2 := s.Seal(KindIP, []byte("x"))
	pkt2[len(pkt2)-1] ^= 1
	if _, _, err := o.Open(pkt2); err != ErrAuth {
		t.Fatalf("tampered packet accepted: %v", err)
	}
}

func TestWrongPassword(t *testing.T) {
	good := DerivePSK("net", "right")
	bad := DerivePSK("net", "wrong")
	eph, _ := NewEphemeral()
	if _, err := ParseHello(good, BuildHello(bad, eph)); err != ErrAuth {
		t.Fatalf("hello with wrong password: %v", err)
	}
	if bytes.Equal(DerivePSK("net-a", "pw"), DerivePSK("net-b", "pw")) {
		t.Fatal("network name not mixed into key")
	}
	// A server that knows a different password cannot complete a handshake.
	cpub := eph.Public()
	welcome, _, _ := ServerHandshake(bad, cpub, 1)
	if _, _, err := ClientFinish(good, eph, welcome); err != ErrAuth {
		t.Fatalf("welcome from wrong server accepted: %v", err)
	}
}

func TestReplayWindow(t *testing.T) {
	var w ReplayWindow
	for _, c := range []uint64{1, 2, 5, 4, 3, 100, 99, 3000} {
		if !w.Check(c) {
			t.Fatalf("fresh counter %d rejected", c)
		}
	}
	for _, c := range []uint64{0, 1, 5, 100, 3000, 10} {
		if w.Check(c) {
			t.Fatalf("counter %d accepted twice or too old", c)
		}
	}
	if !w.Check(2999) || !w.Check(1500) {
		t.Fatal("in-window counter rejected")
	}
}

func TestPeerNoncesDiffer(t *testing.T) {
	key := PairKey([]byte("server-secret-0123456789abcdef01"), "1", "2")
	if !bytes.Equal(key, PairKey([]byte("server-secret-0123456789abcdef01"), "2", "1")) {
		t.Fatal("pair key not symmetric")
	}
	a, _ := NewSealer(key, TypePeer, 1, 1)
	b, _ := NewSealer(key, TypePeer, 2, 2)
	oa, _ := NewOpener(key, 1) // opens what a sends
	ob, _ := NewOpener(key, 2)
	pa, pb := a.Seal(KindPing, []byte("a")), b.Seal(KindPing, []byte("b"))
	if _, _, err := oa.Open(pa); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ob.Open(pb); err != nil {
		t.Fatal(err)
	}
	if _, _, err := oa.Open(b.Seal(KindPing, nil)); err == nil {
		t.Fatal("packet from b opened with a's nonce space")
	}
}

func TestBroadcast(t *testing.T) {
	subnet := netip.MustParsePrefix("10.77.0.0/24")
	for addr, want := range map[string]bool{
		"255.255.255.255": true, "10.77.0.255": true, "224.0.0.251": true, "239.255.255.250": true,
		"10.77.0.5": false, "8.8.8.8": false,
	} {
		if got := IsBroadcastLike(netip.MustParseAddr(addr), subnet); got != want {
			t.Errorf("%s: got %v", addr, got)
		}
	}
	if LastAddr(netip.MustParsePrefix("10.77.0.0/16")).String() != "10.77.255.255" {
		t.Error("LastAddr /16")
	}
}
