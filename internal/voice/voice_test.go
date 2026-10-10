package voice

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/peer"
)

func TestSignalBetweenApps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
	member := true
	members := func(ip netip.Addr) bool { return member && (ip == a || ip == b) }
	hb := peer.NewHub(members)
	Register(hb)
	if err := hb.Listen(ctx, b); err != nil {
		t.Skip("cannot listen on 127.0.0.3:", err)
	}
	defer hb.Close()
	events, stop := hb.Subscribe()
	defer stop()

	// Sent from 127.0.0.2: the receiver identifies the sender by its address.
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: a.AsSlice()}}
	c := &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: d.DialContext}}
	post := func(body string) int {
		resp, err := c.Post(peer.URL(b, signalPath), "application/json", stringsReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(`{"t":"hello","team":2}`); code != http.StatusNoContent {
		t.Fatalf("status %d", code)
	}
	select {
	case ev := <-events:
		if ev.Kind != "signal" || ev.From != a.String() || string(ev.Msg) != `{"t":"hello","team":2}` {
			t.Fatalf("got %+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("signal not delivered")
	}
	member = false
	if code := post(`{}`); code != http.StatusForbidden {
		t.Fatalf("non-member got %d", code)
	}
	if err := Send(ctx, hb, netip.MustParseAddr("127.0.0.9"), json.RawMessage(`{}`)); err == nil {
		t.Fatal("sent to a non-member")
	}

	var ks keyState
	ks.set(hb, true, false)
	if ev := <-events; ev.Kind != "keys" || !ev.Team || ev.All {
		t.Fatalf("keys event %+v", ev)
	}
	ks.set(hb, true, false) // unchanged: no event
	select {
	case ev := <-events:
		t.Fatalf("unexpected %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}
	// A window opened later learns the current key state.
	late, stop2 := hb.Subscribe()
	defer stop2()
	if ev := <-late; ev.Kind != "keys" || !ev.Team {
		t.Fatalf("late window got %+v", ev)
	}
}
