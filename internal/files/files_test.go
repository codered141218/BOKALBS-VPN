package files

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"net/netip"

	"github.com/codered141218/bokalbs-vpn/internal/peer"
	"github.com/codered141218/bokalbs-vpn/internal/share"
)

func TestSafeName(t *testing.T) {
	for in, want := range map[string]string{
		"map.w3x":           "map.w3x",
		`..\..\evil.exe`:    "evil.exe",
		"../../etc/passwd":  "passwd",
		`a<b>:c"d|e?f*.txt`: "a_b__c_d_e_f_.txt",
		"CON.txt":           "_CON.txt",
		"  .. ":             "file",
	} {
		if got := SafeName(in); got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func waitState(t *testing.T, m *Manager, incoming bool, want string) Transfer {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, tr := range m.Transfers() {
			if tr.Incoming == incoming && tr.State == want {
				return tr
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no %v transfer reached %q: %+v", incoming, want, m.Transfers())
	return Transfer{}
}

func TestBrowseDownloadAndSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
	members := func(ip netip.Addr) bool { return ip == a || ip == b }
	names := map[netip.Addr]string{a: "Host", b: "Jaina"}
	nameOf := func(ip netip.Addr) string { return names[ip] }

	ha, hb := peer.NewHub(members), peer.NewHub(members)
	ma := New(ha, nameOf, func() string { return "Host" }, nil)
	mb := New(hb, nameOf, func() string { return "Jaina" }, nil)
	if err := ha.Listen(ctx, a); err != nil {
		t.Skip("cannot listen on 127.0.0.2:", err)
	}
	defer ha.Close()
	if err := hb.Listen(ctx, b); err != nil {
		t.Skip(err)
	}
	defer hb.Close()
	t.Setenv("BOKALBS_DOWNLOADS", t.TempDir())

	// Jaina shares a folder; the host browses and downloads from it.
	shared := t.TempDir()
	os.MkdirAll(filepath.Join(shared, "Maps"), 0o755)
	payload := bytes.Repeat([]byte("dota"), 300000) // 1.2 MB
	os.WriteFile(filepath.Join(shared, "Maps", "DotA LoD.w3x"), payload, 0o644)
	sh, err := share.Start(ctx, b, shared, "Jaina")
	if err != nil {
		t.Skip(err)
	}
	defer sh.Close()

	root, err := ma.List(ctx, b, "/")
	if err != nil || len(root.Entries) != 1 || !root.Entries[0].Dir || root.Owner != "Jaina" {
		t.Fatalf("root listing: %v %+v", err, root)
	}
	maps, err := ma.List(ctx, b, "/Maps")
	if err != nil || len(maps.Entries) != 1 || maps.Entries[0].Size != int64(len(payload)) {
		t.Fatalf("maps listing: %v %+v", err, maps)
	}
	if _, err := ma.Download(b, "/Maps/DotA LoD.w3x", maps.Entries[0].Size); err != nil {
		t.Fatal(err)
	}
	got := waitState(t, ma, true, "done")
	if data, _ := os.ReadFile(got.Path); !bytes.Equal(data, payload) || filepath.Dir(got.Path) != DownloadDir() {
		t.Fatalf("downloaded file wrong: %s (%d bytes)", got.Path, len(data))
	}

	// The host sends a file to Jaina, who accepts it.
	src := filepath.Join(t.TempDir(), "replay.w3g")
	os.WriteFile(src, []byte("replay data"), 0o644)
	events, stop := hb.Subscribe()
	defer stop()
	if err := ma.Send(ctx, b, []string{src}); err != nil {
		t.Fatal(err)
	}
	var offerID string
	select {
	case ev := <-events:
		if ev.Kind != "file-offer" || ev.From != a.String() {
			t.Fatalf("event %+v", ev)
		}
		offers := mb.Offers()
		if len(offers) != 1 || offers[0].FromName != "Host" || offers[0].Files[0].Name != "replay.w3g" {
			t.Fatalf("offers %+v", offers)
		}
		offerID = offers[0].ID
	case <-time.After(3 * time.Second):
		t.Fatal("offer not received")
	}
	waitState(t, ma, false, "waiting")
	if err := mb.Answer(ctx, a, offerID, true); err != nil {
		t.Fatal(err)
	}
	recv := waitState(t, mb, true, "done")
	if data, _ := os.ReadFile(recv.Path); string(data) != "replay data" {
		t.Fatalf("received %q", data)
	}
	waitState(t, ma, false, "done")

	// A declined offer is reported back, and its file can't be fetched.
	if err := ma.Send(ctx, b, []string{src}); err != nil {
		t.Fatal(err)
	}
	<-events
	o := mb.Offers()[0]
	if err := mb.Answer(ctx, a, o.ID, false); err != nil {
		t.Fatal(err)
	}
	waitState(t, ma, false, "declined")
	if resp, err := hb.Stream(ctx, a, "GET", "/files/xfer/"+o.Files[0].Token, nil); err == nil {
		resp.Body.Close()
		t.Fatal("declined file could still be downloaded")
	}
	// Only the member the file was offered to may fetch it.
	if err := ma.Send(ctx, b, []string{src}); err != nil {
		t.Fatal(err)
	}
	<-events
	tok := mb.Offers()[0].Files[0].Token
	if resp, err := ha.Stream(ctx, a, "GET", "/files/xfer/"+tok, nil); err == nil {
		resp.Body.Close()
		t.Fatal("a different member could fetch the offered file")
	}
}
