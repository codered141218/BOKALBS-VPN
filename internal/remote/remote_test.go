//go:build !windows

package remote

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"image/jpeg"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/peer"
)

type pipeWriter struct{ w *io.PipeWriter }

func (p pipeWriter) Write(b []byte) (int, error) { return p.w.Write(b) }

func TestRemoteSession(t *testing.T) {
	t.Setenv("BOKALBS_FAKE_SCREEN", "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	viewerIP, targetIP := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
	members := func(ip netip.Addr) bool { return ip == viewerIP || ip == targetIP }
	name := func(ip netip.Addr) string { return map[netip.Addr]string{viewerIP: "Host", targetIP: "Jaina"}[ip] }
	hv, ht := peer.NewHub(members), peer.NewHub(members)
	logf := func(f string, a ...any) { t.Logf(f, a...) }
	viewer, target := New(hv, name, nil, logf, nil, nil), New(ht, name, nil, logf, nil, nil)
	if err := hv.Listen(ctx, viewerIP); err != nil {
		t.Skip(err)
	}
	defer hv.Close()
	if err := ht.Listen(ctx, targetIP); err != nil {
		t.Skip(err)
	}
	defer ht.Close()
	tEvents, stopT := ht.Subscribe()
	defer stopT()
	vEvents, stopV := hv.Subscribe()
	defer stopV()

	next := func(ch <-chan peer.Event, kind string) Session {
		t.Helper()
		select {
		case ev := <-ch:
			var s Session
			json.Unmarshal(ev.Msg, &s)
			if ev.Kind != kind {
				t.Fatalf("got %s, want %s", ev.Kind, kind)
			}
			return s
		case <-time.After(3 * time.Second):
			t.Fatalf("no %s event", kind)
		}
		return Session{}
	}

	// A denied request.
	id, err := viewer.Request(ctx, targetIP, true, "", false)
	if err != nil {
		t.Fatal(err)
	}
	req := next(tEvents, "remote-request")
	if req.PeerName != "Host" || !req.Control || req.ID != id {
		t.Fatalf("request %+v", req)
	}
	if err := target.Answer(ctx, id, false, false, false); err != nil {
		t.Fatal(err)
	}
	if s := next(vEvents, "remote-answer"); s.State != "declined" {
		t.Fatalf("answer %+v", s)
	}
	if err := viewer.Stream(ctx, id, io.Discard, func() {}); err == nil {
		t.Fatal("streamed a declined session")
	}

	// An allowed request, with control.
	id, _ = viewer.Request(ctx, targetIP, true, "", false)
	next(tEvents, "remote-request")
	if err := target.Answer(ctx, id, true, true, false); err != nil {
		t.Fatal(err)
	}
	if s := next(vEvents, "remote-answer"); s.State != "active" || !s.Control {
		t.Fatalf("answer %+v", s)
	}
	pr, pw := io.Pipe()
	go func() {
		err := viewer.Stream(ctx, id, pipeWriter{pw}, func() {})
		pw.CloseWithError(err)
	}()
	br := bufio.NewReader(pr)
	readMsg := func() (byte, []byte) {
		typ, err := br.ReadByte()
		if err != nil {
			t.Fatal(err)
		}
		switch typ {
		case msgSize:
			b := make([]byte, 4)
			io.ReadFull(br, b)
			return typ, b
		case msgTile:
			h := make([]byte, 12)
			io.ReadFull(br, h)
			data := make([]byte, binary.BigEndian.Uint32(h[8:12]))
			io.ReadFull(br, data)
			return typ, append(h[:8], data...)
		}
		return typ, nil
	}
	typ, size := readMsg()
	if typ != msgSize || binary.BigEndian.Uint16(size[0:2]) != 640 || binary.BigEndian.Uint16(size[2:4]) != 360 {
		t.Fatalf("first message %c %v", typ, size)
	}
	// First frame: every tile (5 x 3); later frames: only tiles the moving square touched.
	tiles, frames, perFrame := 0, 0, []int{}
	for frames < 4 {
		typ, body := readMsg()
		switch typ {
		case msgTile:
			if _, err := jpeg.Decode(bytes.NewReader(body[8:])); err != nil {
				t.Fatalf("tile is not a JPEG: %v", err)
			}
			tiles++
		case msgFrame:
			perFrame = append(perFrame, tiles)
			tiles = 0
			frames++
		}
	}
	if perFrame[0] != 15 || perFrame[2] == 0 || perFrame[2] > 3 {
		t.Fatalf("tiles per frame %v: want 15 first, then only changed ones", perFrame)
	}

	// Input reaches the target.
	evs := json.RawMessage(`[{"t":"move","x":0.5,"y":0.25},{"t":"down","b":0,"x":0.5,"y":0.25},{"t":"key","k":65}]`)
	if err := viewer.Input(ctx, id, evs); err != nil {
		t.Fatal(err)
	}
	if rec := Recorded(); len(rec) != 3 || rec[0].X != 0.5 || rec[2].K != 65 {
		t.Fatalf("recorded %+v", rec)
	}

	// Another member can't use the session token.
	if resp, err := ht.Stream(ctx, targetIP, "GET", "/remote/stream?id="+id+"&token=x", nil); err == nil {
		resp.Body.Close()
		t.Fatal("stream without the right token")
	}

	// The person being viewed stops the session: the viewer is told and the stream ends.
	target.Stop(ctx, id)
	if s := next(vEvents, "remote-ended"); s.State != "ended" {
		t.Fatalf("ended %+v", s)
	}
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, br); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stream kept running after stop")
	}
	if err := viewer.Input(ctx, id, evs); err == nil {
		t.Fatal("input accepted after stop")
	}
}

func TestViewOnly(t *testing.T) {
	t.Setenv("BOKALBS_FAKE_SCREEN", "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := netip.MustParseAddr("127.0.0.4"), netip.MustParseAddr("127.0.0.5")
	members := func(ip netip.Addr) bool { return ip == a || ip == b }
	ha, hb := peer.NewHub(members), peer.NewHub(members)
	name := func(netip.Addr) string { return "x" }
	va, vb := New(ha, name, nil, t.Logf, nil, nil), New(hb, name, nil, t.Logf, nil, nil)
	if ha.Listen(ctx, a) != nil || hb.Listen(ctx, b) != nil {
		t.Skip("cannot listen")
	}
	defer ha.Close()
	defer hb.Close()
	ev, stop := hb.Subscribe()
	defer stop()
	id, _ := va.Request(ctx, b, true, "", false)
	<-ev
	vb.Answer(ctx, id, true, false, false) // view only
	time.Sleep(200 * time.Millisecond)
	if err := va.Input(ctx, id, json.RawMessage(`[{"t":"key","k":65}]`)); err == nil {
		t.Fatal("input allowed in a view-only session")
	}
}

type testPolicy struct {
	mu       sync.Mutex
	password string
	trusted  map[string]bool // key -> control
}

func (p *testPolicy) Trusted(k ed25519.PublicKey) (bool, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.trusted[string(k)]
	return ok, c
}
func (p *testPolicy) CheckPassword(pw string) bool { return p.password != "" && pw == p.password }
func (p *testPolicy) Trust(k ed25519.PublicKey, name string, control bool) {
	p.mu.Lock()
	p.trusted[string(k)] = control
	p.mu.Unlock()
}

func TestUnattendedAccess(t *testing.T) {
	t.Setenv("BOKALBS_FAKE_SCREEN", "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vIP, tIP, xIP := netip.MustParseAddr("127.0.0.6"), netip.MustParseAddr("127.0.0.7"), netip.MustParseAddr("127.0.0.8")
	members := func(ip netip.Addr) bool { return ip == vIP || ip == tIP || ip == xIP }
	name := func(ip netip.Addr) string { return ip.String() }
	hv, ht, hx := peer.NewHub(members), peer.NewHub(members), peer.NewHub(members)
	pol := &testPolicy{password: "office-pc-2026", trusted: map[string]bool{}}
	viewer := New(hv, name, nil, t.Logf, bytes.Repeat([]byte{1}, 32), nil)
	target := New(ht, name, nil, t.Logf, nil, pol)
	other := New(hx, name, nil, t.Logf, bytes.Repeat([]byte{2}, 32), nil)
	for ip, h := range map[netip.Addr]*peer.Hub{vIP: hv, tIP: ht, xIP: hx} {
		if err := h.Listen(ctx, ip); err != nil {
			t.Skip(err)
		}
		defer h.Close()
	}
	vEv, s1 := hv.Subscribe()
	defer s1()
	tEv, s2 := ht.Subscribe()
	defer s2()
	xEv, s3 := hx.Subscribe()
	defer s3()
	expect := func(ch <-chan peer.Event, kind string) Session {
		t.Helper()
		for {
			select {
			case ev := <-ch:
				if ev.Kind == kind {
					var s Session
					json.Unmarshal(ev.Msg, &s)
					return s
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("no %s event", kind)
			}
		}
	}
	quiet := func(ch <-chan peer.Event, kind string) {
		t.Helper()
		deadline := time.After(400 * time.Millisecond)
		for {
			select {
			case ev := <-ch:
				if ev.Kind == kind {
					t.Fatalf("unexpected %s", kind)
				}
			case <-deadline:
				return
			}
		}
	}

	// Wrong password: refused, nobody asked.
	if _, err := viewer.Request(ctx, tIP, true, "guess", false); err == nil || !strings.Contains(err.Error(), "wrong password") {
		t.Fatalf("wrong password: %v", err)
	}
	quiet(tEv, "remote-request")

	// Right password, remember this PC: starts at once, no dialog.
	id, err := viewer.Request(ctx, tIP, true, "office-pc-2026", true)
	if err != nil {
		t.Fatal(err)
	}
	if s := expect(vEv, "remote-answer"); s.ID != id || s.State != "active" || !s.Control || !s.Unattended {
		t.Fatalf("answer %+v", s)
	}
	if s := expect(tEv, "remote-started"); !s.Unattended || !s.Incoming {
		t.Fatalf("target sees %+v", s)
	}
	if ok, ctl := pol.Trusted(viewer.DeviceKey()); !ok || !ctl {
		t.Fatal("viewer was not remembered")
	}
	target.Stop(ctx, id)
	expect(vEv, "remote-ended")

	// Trusted now: no password needed, still no dialog.
	id, err = viewer.Request(ctx, tIP, true, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if s := expect(vEv, "remote-answer"); s.ID != id || s.State != "active" {
		t.Fatalf("trusted answer %+v", s)
	}
	quiet(tEv, "remote-request")
	target.Stop(ctx, id)
	expect(vEv, "remote-ended")

	// Another member with a different device key is asked as usual.
	oid, err := other.Request(ctx, tIP, true, "", false)
	if err != nil {
		t.Fatal(err)
	}
	expect(tEv, "remote-request")
	quiet(xEv, "remote-answer")
	other.Stop(ctx, oid)

	// Lockout after 5 wrong passwords, even the right one is refused for a while.
	for i := 0; i < 5; i++ {
		other.Request(ctx, tIP, true, "nope", false)
	}
	if _, err := other.Request(ctx, tIP, true, "office-pc-2026", false); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("expected lockout, got %v", err)
	}

	// Removing trust makes the viewer ask again.
	pol.mu.Lock()
	pol.trusted = map[string]bool{}
	pol.mu.Unlock()
	if _, err := viewer.Request(ctx, tIP, true, "", false); err != nil {
		t.Fatal(err)
	}
	expect(tEv, "remote-request")
	quiet(vEv, "remote-answer")
}
