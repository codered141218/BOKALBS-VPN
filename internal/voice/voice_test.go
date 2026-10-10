package voice

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

func TestSignalBetweenApps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
	members := func(ip netip.Addr) bool { return ip == a || ip == b }
	ha, hb := NewHub(members), NewHub(members)
	if err := hb.Listen(ctx, b); err != nil {
		t.Skip("cannot listen on 127.0.0.3:", err)
	}
	defer hb.Close()

	events, stop := hb.Subscribe()
	defer stop()
	if ev := <-events; ev.Kind != "keys" {
		t.Fatalf("first event %+v", ev)
	}

	// Sent from 127.0.0.2: bind the client to a's address so b sees it as the sender.
	ha.client.Transport.(*httpTransport).DialContext = dialFrom(a)
	if err := ha.Send(ctx, b, json.RawMessage(`{"t":"hello","team":2}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-events:
		if ev.Kind != "signal" || ev.From != a.String() || string(ev.Msg) != `{"t":"hello","team":2}` {
			t.Fatalf("got %+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("signal not delivered")
	}

	// Strangers are refused.
	hb.IsMember = func(ip netip.Addr) bool { return false }
	if err := ha.Send(ctx, b, json.RawMessage(`{}`)); err == nil {
		t.Fatal("message from a non-member accepted")
	}
	if err := ha.Send(ctx, netip.MustParseAddr("127.0.0.9"), json.RawMessage(`{}`)); err == nil {
		t.Fatal("sent to a non-member")
	}

	hb.SetKeys(true, false)
	if ev := <-events; ev.Kind != "keys" || !ev.Team || ev.All {
		t.Fatalf("keys event %+v", ev)
	}
	hb.SetKeys(true, false) // unchanged: no event
	select {
	case ev := <-events:
		t.Fatalf("unexpected %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}
}
