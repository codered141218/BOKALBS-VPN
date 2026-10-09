// Package rvtest provides in-process stand-ins for the public services used
// for connecting without port forwarding: an ntfy-compatible message server
// and a STUN server. They are used by tests.
package rvtest

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/stun"
)

type message struct {
	ID      string `json:"id"`
	Time    int64  `json:"time"`
	Event   string `json:"event"`
	Topic   string `json:"topic"`
	Message string `json:"message,omitempty"`
}

// Ntfy is a minimal ntfy-compatible server: POST /topic publishes,
// GET /topic/json?poll=1&since=Ns polls, GET /topic/json streams.
type Ntfy struct {
	mu     sync.Mutex
	msgs   map[string][]message
	subs   map[string][]chan message
	nextID int
}

func NewNtfy() *Ntfy {
	return &Ntfy{msgs: map[string][]message{}, subs: map[string][]chan message{}}
}

func (n *Ntfy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(r.URL.Path, "/")
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		n.mu.Lock()
		n.nextID++
		m := message{ID: fmt.Sprint(n.nextID), Time: time.Now().Unix(), Event: "message", Topic: path, Message: string(body)}
		n.msgs[path] = append(n.msgs[path], m)
		for _, ch := range n.subs[path] {
			select {
			case ch <- m:
			default:
			}
		}
		n.mu.Unlock()
		_ = json.NewEncoder(w).Encode(m)
		return
	}
	topic, ok := strings.CutSuffix(path, "/json")
	if !ok {
		http.NotFound(w, r)
		return
	}
	enc := json.NewEncoder(w)
	if r.URL.Query().Get("poll") == "1" {
		var since time.Duration
		if s := r.URL.Query().Get("since"); s != "" && s != "all" {
			since, _ = time.ParseDuration(s)
		}
		n.mu.Lock()
		msgs := append([]message(nil), n.msgs[topic]...)
		n.mu.Unlock()
		for _, m := range msgs {
			if since == 0 || time.Since(time.Unix(m.Time, 0)) <= since {
				_ = enc.Encode(m)
			}
		}
		return
	}
	ch := make(chan message, 16)
	n.mu.Lock()
	n.subs[topic] = append(n.subs[topic], ch)
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		subs := n.subs[topic]
		for i, c := range subs {
			if c == ch {
				n.subs[topic] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		n.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "application/x-ndjson")
	_ = enc.Encode(message{Event: "open", Topic: topic, Time: time.Now().Unix()})
	w.(http.Flusher).Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case m := <-ch:
			_ = enc.Encode(m)
			w.(http.Flusher).Flush()
		}
	}
}

// ServeSTUN answers STUN binding requests on conn until it is closed.
func ServeSTUN(conn *net.UDPConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if stun.IsRequest(buf[:n]) {
			_, _ = conn.WriteToUDPAddrPort(stun.BuildResponse(buf[:n], from), from)
		}
	}
}
