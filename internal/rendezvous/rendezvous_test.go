package rendezvous_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/rendezvous"
	"github.com/codered141218/bokalbs-vpn/internal/rendezvous/rvtest"
)

func TestPublishPollSubscribe(t *testing.T) {
	srv := httptest.NewServer(rvtest.NewNtfy())
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	host := rendezvous.New(srv.URL, []byte("psk-of-the-network-0123456789abc"))
	player := rendezvous.New(srv.URL, []byte("psk-of-the-network-0123456789abc"))
	stranger := rendezvous.New(srv.URL, []byte("a-different-password-key-xxxxxxx"))
	if host.Topic() != player.Topic() || host.Topic() == stranger.Topic() {
		t.Fatal("topic must depend on the password only")
	}

	got := make(chan rendezvous.Message, 4)
	go host.Subscribe(ctx, func(m rendezvous.Message) { got <- m })
	time.Sleep(100 * time.Millisecond)

	if err := host.Publish(ctx, rendezvous.Message{Role: rendezvous.RoleHost, Endpoints: []string{"203.0.113.7:47820"}}); err != nil {
		t.Fatal(err)
	}
	m, err := player.Latest(ctx, rendezvous.RoleHost, time.Hour)
	if err != nil || m.Endpoints[0] != "203.0.113.7:47820" {
		t.Fatalf("latest: %v %+v", err, m)
	}
	if _, err := player.Latest(ctx, rendezvous.RoleKnock, time.Hour); err != rendezvous.ErrNotFound {
		t.Fatalf("expected not found, got %v", err)
	}

	// Forged message on the right topic (someone without the password) is ignored.
	httpPost(t, srv.URL+"/"+host.Topic(), "garbage-not-encrypted")

	_ = player.Publish(ctx, rendezvous.Message{Role: rendezvous.RoleKnock, Endpoints: []string{"198.51.100.9:5000"}})
	for {
		select {
		case m := <-got:
			if m.Role == rendezvous.RoleKnock {
				if m.Endpoints[0] != "198.51.100.9:5000" {
					t.Fatalf("knock %+v", m)
				}
				return
			}
		case <-time.After(3 * time.Second):
			t.Fatal("subscriber did not receive the knock")
		}
	}
}

func httpPost(t *testing.T, url, body string) {
	t.Helper()
	resp, err := http.Post(url, "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
