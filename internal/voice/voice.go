// Package voice supports the app's voice chat.
//
// The audio itself is handled by WebRTC in the app window (Opus codec, echo
// cancellation, noise suppression) and flows directly between players over
// the VPN. This package carries the small setup messages WebRTC needs
// (offers, answers, network candidates) from one player's app to another's,
// and reports push-to-talk keys pressed anywhere, even while a game has
// focus.
package voice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// Port is where apps exchange voice setup messages (VPN address only).
const Port = 47822

// Event goes to the app window.
type Event struct {
	Kind string          `json:"kind"`           // "signal" or "keys"
	From string          `json:"from,omitempty"` // VPN address of the sender (signal)
	Msg  json.RawMessage `json:"msg,omitempty"`  // signal payload, opaque to Go
	Team bool            `json:"team,omitempty"` // talk-to-team key held (keys)
	All  bool            `json:"all,omitempty"`  // talk-to-everyone key held (keys)
}

// Hub fans events out to the open app windows and talks to other apps.
type Hub struct {
	// IsMember reports whether an address belongs to the VPN network.
	IsMember func(netip.Addr) bool

	mu   sync.Mutex
	subs map[chan Event]struct{}
	keys Event
	srv  *http.Server
	ip   netip.Addr

	client *http.Client
}

func NewHub(isMember func(netip.Addr) bool) *Hub {
	return &Hub{
		IsMember: isMember,
		subs:     map[chan Event]struct{}{},
		keys:     Event{Kind: "keys"},
		client:   &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: nil}},
	}
}

// Subscribe returns a channel of events; call cancel when done.
func (h *Hub) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	keys := h.keys
	h.mu.Unlock()
	ch <- keys
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

func (h *Hub) publish(ev Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- ev:
		default: // a slow window misses an event rather than blocking voice
		}
	}
}

// SetKeys reports the push-to-talk keys' state.
func (h *Hub) SetKeys(team, all bool) {
	h.mu.Lock()
	changed := h.keys.Team != team || h.keys.All != all
	h.keys.Team, h.keys.All = team, all
	h.mu.Unlock()
	if changed {
		h.publish(Event{Kind: "keys", Team: team, All: all})
	}
}

// Listen accepts setup messages from other apps on ip:Port. It replaces a
// previous listener (for example after the VPN address changed). Windows
// needs a moment before a new address can be used, so it retries.
func (h *Hub) Listen(ctx context.Context, ip netip.Addr) error {
	h.mu.Lock()
	if h.srv != nil && h.ip == ip {
		h.mu.Unlock()
		return nil
	}
	old := h.srv
	h.srv = nil
	h.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	addr := netip.AddrPortFrom(ip, Port).String()
	var ln net.Listener
	var err error
	for try := 0; ; try++ {
		if ln, err = net.Listen("tcp4", addr); err == nil {
			break
		}
		if try >= 30 {
			return fmt.Errorf("voice chat cannot listen on %s: %w", addr, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	srv := &http.Server{Handler: http.HandlerFunc(h.serveSignal), ReadHeaderTimeout: 5 * time.Second}
	h.mu.Lock()
	h.srv, h.ip = srv, ip
	h.mu.Unlock()
	go srv.Serve(ln)
	return nil
}

// Close stops listening.
func (h *Hub) Close() {
	h.mu.Lock()
	srv := h.srv
	h.srv, h.ip = nil, netip.Addr{}
	h.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

func (h *Hub) serveSignal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/voice/signal" {
		http.NotFound(w, r)
		return
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !h.IsMember(ap.Addr().Unmap()) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil || !json.Valid(body) {
		http.Error(w, "bad message", http.StatusBadRequest)
		return
	}
	h.publish(Event{Kind: "signal", From: ap.Addr().Unmap().String(), Msg: body})
	w.WriteHeader(http.StatusNoContent)
}

// Send delivers a setup message to another member's app.
func (h *Hub) Send(ctx context.Context, to netip.Addr, msg json.RawMessage) error {
	if !h.IsMember(to) {
		return fmt.Errorf("%s is not on the VPN", to)
	}
	if !json.Valid(msg) || len(msg) > 64<<10 {
		return fmt.Errorf("invalid message")
	}
	url := "http://" + netip.AddrPortFrom(to, Port).String() + "/voice/signal"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(msg))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s answered %s", to, resp.Status)
	}
	return nil
}
