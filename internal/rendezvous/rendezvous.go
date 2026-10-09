// Package rendezvous lets the host and players of a network find each other
// without port forwarding, through a free public message service (ntfy.sh).
//
// Members exchange their public UDP addresses there, then punch through their
// routers. Every message is encrypted and authenticated with a key derived
// from the network password; the service only sees random-looking text on a
// topic whose name is also derived from the password.
package rendezvous

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// DefaultURL is the public ntfy server. Set BOKALBS_RENDEZVOUS to override.
const DefaultURL = "https://ntfy.sh"

// URL returns the rendezvous service to use.
func URL() string {
	if u := os.Getenv("BOKALBS_RENDEZVOUS"); u != "" {
		return u
	}
	return DefaultURL
}

const (
	RoleHost  = "host"  // the server announcing where it can be reached
	RoleKnock = "knock" // a player asking the server to punch towards it
)

// Message is what members tell each other.
type Message struct {
	Role      string   `json:"r"`
	Endpoints []string `json:"e"` // UDP addresses, best first
	Time      int64    `json:"t"` // unix seconds
	Nonce     string   `json:"n,omitempty"`
}

// Client talks to the rendezvous service for one network.
type Client struct {
	base  string
	topic string
	aead  cipher.AEAD
	http  *http.Client
}

// New creates a client for the network whose pre-shared key is psk.
func New(base string, psk []byte) *Client {
	key := make([]byte, 32)
	_, _ = io.ReadFull(hkdf.New(sha256.New, psk, nil, []byte("bokalbs-vpn/v1/rendezvous")), key)
	sum := sha256.Sum256(append(append([]byte(nil), key...), "topic"...))
	aead, _ := chacha20poly1305.NewX(key)
	return &Client{
		base:  strings.TrimRight(base, "/"),
		topic: "bokalbs_" + hex.EncodeToString(sum[:12]),
		aead:  aead,
		http:  &http.Client{Timeout: 15 * time.Second},
	}
}

// Topic is the (password-derived) topic name used on the service.
func (c *Client) Topic() string { return c.topic }

func (c *Client) seal(m Message) string {
	b, _ := json.Marshal(m)
	nonce := make([]byte, c.aead.NonceSize())
	_, _ = rand.Read(nonce)
	out := c.aead.Seal(nonce, nonce, b, []byte(c.topic))
	return base64.RawURLEncoding.EncodeToString(out)
}

func (c *Client) open(s string) (Message, bool) {
	var m Message
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) < c.aead.NonceSize()+c.aead.Overhead() {
		return m, false
	}
	plain, err := c.aead.Open(nil, raw[:c.aead.NonceSize()], raw[c.aead.NonceSize():], []byte(c.topic))
	if err != nil || json.Unmarshal(plain, &m) != nil {
		return m, false
	}
	return m, true
}

// Publish posts a message for the other members.
func (c *Client) Publish(ctx context.Context, m Message) error {
	if m.Time == 0 {
		m.Time = time.Now().Unix()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/"+c.topic, strings.NewReader(c.seal(m)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the rendezvous service: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("rendezvous service answered %s", resp.Status)
	}
	return nil
}

type event struct {
	Event   string `json:"event"`
	Message string `json:"message"`
}

func (c *Client) decodeStream(r io.Reader, fn func(Message)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		var ev event
		if json.Unmarshal(bytes.TrimSpace(sc.Bytes()), &ev) != nil || ev.Event != "message" {
			continue
		}
		if m, ok := c.open(ev.Message); ok {
			fn(m)
		}
	}
	return sc.Err()
}

// Poll returns the messages posted in the last `since`.
func (c *Client) Poll(ctx context.Context, since time.Duration) ([]Message, error) {
	q := url.Values{"poll": {"1"}, "since": {fmt.Sprintf("%ds", int(since.Seconds()))}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/"+c.topic+"/json?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the rendezvous service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("rendezvous service answered %s", resp.Status)
	}
	var out []Message
	err = c.decodeStream(io.LimitReader(resp.Body, 1<<20), func(m Message) { out = append(out, m) })
	return out, err
}

// Latest returns the newest message with the given role posted within since.
func (c *Client) Latest(ctx context.Context, role string, since time.Duration) (Message, error) {
	msgs, err := c.Poll(ctx, since)
	if err != nil {
		return Message{}, err
	}
	var best Message
	for _, m := range msgs {
		if m.Role == role && m.Time >= best.Time {
			best = m
		}
	}
	if best.Role == "" {
		return best, ErrNotFound
	}
	return best, nil
}

// ErrNotFound means nobody has announced themselves yet.
var ErrNotFound = errors.New("not found")

// Subscribe calls fn for every new message until ctx is cancelled,
// reconnecting when the connection drops.
func (c *Client) Subscribe(ctx context.Context, fn func(Message)) {
	stream := &http.Client{} // no timeout: the response is a long-lived stream
	for ctx.Err() == nil {
		sctx, cancel := context.WithCancel(ctx)
		req, _ := http.NewRequestWithContext(sctx, http.MethodGet, c.base+"/"+c.topic+"/json", nil)
		resp, err := stream.Do(req)
		if err == nil {
			// ntfy sends a keepalive every 45s; treat 2 minutes of silence as a dead connection.
			alive := make(chan struct{}, 1)
			go func() {
				t := time.NewTimer(2 * time.Minute)
				defer t.Stop()
				for {
					select {
					case <-sctx.Done():
						return
					case <-alive:
						t.Reset(2 * time.Minute)
					case <-t.C:
						cancel()
						return
					}
				}
			}()
			sc := bufio.NewScanner(resp.Body)
			for sc.Scan() {
				select {
				case alive <- struct{}{}:
				default:
				}
				var ev event
				if json.Unmarshal(bytes.TrimSpace(sc.Bytes()), &ev) == nil && ev.Event == "message" {
					if m, ok := c.open(ev.Message); ok {
						fn(m)
					}
				}
			}
			resp.Body.Close()
		}
		cancel()
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}
