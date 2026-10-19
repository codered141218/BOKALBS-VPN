// Package peer is the channel between members' apps over the VPN.
//
// Every app listens on its VPN address (port 47822) for small requests from
// other members (voice chat setup, file offers, remote desktop requests) and
// streams (file transfers, screen sharing). Only VPN members are answered.
// The same Hub is the app's event bus towards its own window.
package peer

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

// Port is where apps talk to each other (VPN address only).
const Port = 47822

// Event goes to the app window.
type Event struct {
	Kind string          `json:"kind"`
	From string          `json:"from,omitempty"` // VPN address of the member it came from
	Msg  json.RawMessage `json:"msg,omitempty"`
	Team bool            `json:"team,omitempty"` // voice keys
	All  bool            `json:"all,omitempty"`
}

// HandlerFunc serves a request from the member at from.
type HandlerFunc func(w http.ResponseWriter, r *http.Request, from netip.Addr)

// Hub fans events out to the window and talks to other members' apps.
type Hub struct {
	// IsMember reports whether an address belongs to the VPN network.
	IsMember func(netip.Addr) bool

	mu    sync.Mutex
	subs  map[chan Event]struct{}
	last  map[string]Event // latest event per sticky kind, replayed to new windows
	srv   *http.Server
	ip    netip.Addr
	mux   *http.ServeMux
	short *http.Client
	long  *http.Client
}

func NewHub(isMember func(netip.Addr) bool) *Hub {
	h := &Hub{
		IsMember: isMember,
		subs:     map[chan Event]struct{}{},
		last:     map[string]Event{},
		mux:      http.NewServeMux(),
	}
	tr := &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 4, IdleConnTimeout: time.Minute, DialContext: h.dial}
	h.short = &http.Client{Timeout: 6 * time.Second, Transport: tr}
	h.long = &http.Client{Transport: tr} // streams: no overall timeout
	return h
}

// dial connects from this PC's VPN address, which is how the other app
// knows who is asking.
func (h *Hub) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	h.mu.Lock()
	ip := h.ip
	h.mu.Unlock()
	d := &net.Dialer{Timeout: 5 * time.Second}
	if ip.IsValid() {
		d.LocalAddr = &net.TCPAddr{IP: ip.AsSlice()}
	}
	return d.DialContext(ctx, network, addr)
}

// Handle registers a handler for requests from members.
func (h *Hub) Handle(path string, fn HandlerFunc) {
	h.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !h.IsMember(ap.Addr().Unmap()) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		fn(w, r, ap.Addr().Unmap())
	})
}

// Subscribe returns a channel of events; call cancel when done.
func (h *Hub) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 256)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	for _, ev := range h.last {
		ch <- ev
	}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

// Publish sends an event to the open windows.
func (h *Hub) Publish(ev Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- ev:
		default: // a slow window misses an event rather than blocking everything
		}
	}
}

// PublishSticky publishes ev and replays it to windows opened later.
func (h *Hub) PublishSticky(ev Event) {
	h.mu.Lock()
	h.last[ev.Kind] = ev
	h.mu.Unlock()
	h.Publish(ev)
}

// Listen serves other members on ip:Port. It replaces a previous listener
// (for example after the VPN address changed). Windows needs a moment
// before a new address can be used, so it retries.
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
			return fmt.Errorf("cannot listen on %s: %w", addr, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	srv := &http.Server{Handler: h.mux, ReadHeaderTimeout: 10 * time.Second}
	h.mu.Lock()
	h.srv, h.ip = srv, ip
	h.mu.Unlock()
	go srv.Serve(ln)
	return nil
}

// LocalIP is this PC's VPN address (invalid while not listening).
func (h *Hub) LocalIP() netip.Addr {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ip
}

// Close stops serving other members.
func (h *Hub) Close() {
	h.mu.Lock()
	srv := h.srv
	h.srv, h.ip = nil, netip.Addr{}
	h.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// URL returns the address of path on a member's app.
func URL(to netip.Addr, path string) string {
	return "http://" + netip.AddrPortFrom(to, Port).String() + path
}

// Post sends a small JSON message to a member's app.
func (h *Hub) Post(ctx context.Context, to netip.Addr, path string, body any) error {
	if !h.IsMember(to) {
		return fmt.Errorf("%s is not on the VPN", to)
	}
	var b []byte
	switch v := body.(type) {
	case json.RawMessage:
		b = v
	case []byte:
		b = v
	default:
		var err error
		if b, err = json.Marshal(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, URL(to, path), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.short.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", to, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s answered %s: %s", to, resp.Status, bytes.TrimSpace(msg))
	}
	return nil
}

// Stream starts a long-lived request (file transfer, screen) to a member.
func (h *Hub) Stream(ctx context.Context, to netip.Addr, method, path string, body io.Reader) (*http.Response, error) {
	if !h.IsMember(to) {
		return nil, fmt.Errorf("%s is not on the VPN", to)
	}
	req, err := http.NewRequestWithContext(ctx, method, URL(to, path), body)
	if err != nil {
		return nil, err
	}
	resp, err := h.long.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", to, err)
	}
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("%s answered %s: %s", to, resp.Status, bytes.TrimSpace(msg))
	}
	return resp, nil
}

// ReadJSON decodes a small JSON request body.
func ReadJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(v)
}
