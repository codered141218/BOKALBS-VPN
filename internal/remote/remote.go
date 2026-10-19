// Package remote lets a member see, and if allowed control, another
// member's screen, after asking: the other person must click Allow every
// time, sees a banner while it runs, and can stop it at any moment.
//
// The screen is cut into tiles; only tiles that changed are sent, as JPEG
// images, at up to 12 frames per second. Mouse and keyboard input goes the
// other way. Everything runs directly between the two apps over the VPN.
package remote

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/peer"
)

// Session is a remote desktop session, seen from this PC.
type Session struct {
	ID       string `json:"id"`
	Incoming bool   `json:"incoming"` // true: someone views this PC
	PeerIP   string `json:"peerIp"`
	PeerName string `json:"peerName"`
	Control  bool   `json:"control"` // mouse and keyboard allowed
	State    string `json:"state"`   // asking, active, declined, ended
	Error    string `json:"error,omitempty"`
	// Unattended is true when it started without anyone clicking Allow
	// (trusted PC or access password).
	Unattended bool `json:"unattended,omitempty"`

	token  string
	cancel context.CancelFunc
	ended  time.Time
	pub    ed25519.PublicKey // requester's device key (incoming sessions)
}

// Policy decides about requests without asking the person at the PC.
type Policy interface {
	// Trusted reports whether a device key may connect without asking, and
	// whether it may control the PC (else view only).
	Trusted(key ed25519.PublicKey) (ok, control bool)
	// CheckPassword reports whether unattended access is on and pw is its
	// password.
	CheckPassword(pw string) bool
	// Trust remembers a device key as a trusted PC.
	Trust(key ed25519.PublicKey, name string, control bool)
}

// request is what a viewer sends to ask for a session. It is signed with
// the viewer's device key so a trusted PC can't be impersonated.
type request struct {
	ID       string `json:"id"`
	Control  bool   `json:"control"`
	Key      []byte `json:"key"` // Ed25519 public key
	Time     int64  `json:"time"`
	Sig      []byte `json:"sig"`
	Password string `json:"password,omitempty"` // unattended access password
	Remember bool   `json:"remember,omitempty"` // ask to be trusted next time
}

func signedBytes(id string, target netip.Addr, t int64, control bool) []byte {
	return []byte(fmt.Sprintf("bokalbs-remote-v1\x00%s\x00%s\x00%d\x00%t", id, target, t, control))
}

// InputEvent is mouse or keyboard input from the viewer. X and Y are
// relative to the screen (0..1).
type InputEvent struct {
	T  string  `json:"t"` // move, down, up, wheel, key
	X  float64 `json:"x,omitempty"`
	Y  float64 `json:"y,omitempty"`
	B  int     `json:"b,omitempty"`  // mouse button: 0 left, 1 middle, 2 right
	D  int     `json:"d,omitempty"`  // wheel: positive = away from the user
	K  uint16  `json:"k,omitempty"`  // Windows virtual-key code
	Up bool    `json:"up,omitempty"` // key released
}

// Manager keeps track of sessions.
type Manager struct {
	hub       *peer.Hub
	nameOf    func(netip.Addr) string
	attention func()
	logf      func(string, ...any)
	key       ed25519.PrivateKey
	policy    Policy

	mu       sync.Mutex
	sessions map[string]*Session
	failures map[string][]time.Time // wrong passwords per member
}

// New creates a manager and registers its requests on the peer channel.
// deviceKey is this installation's Ed25519 seed; policy may be nil (always
// ask).
func New(hub *peer.Hub, nameOf func(netip.Addr) string, attention func(), logf func(string, ...any), deviceKey []byte, policy Policy) *Manager {
	if len(deviceKey) != ed25519.SeedSize {
		deviceKey = make([]byte, ed25519.SeedSize)
		_, _ = rand.Read(deviceKey)
	}
	m := &Manager{hub: hub, nameOf: nameOf, attention: attention, logf: logf, key: ed25519.NewKeyFromSeed(deviceKey),
		policy: policy, sessions: map[string]*Session{}, failures: map[string][]time.Time{}}
	hub.Handle("/remote/request", m.serveRequest)
	hub.Handle("/remote/answer", m.serveAnswer)
	hub.Handle("/remote/stop", m.serveStop)
	hub.Handle("/remote/stream", m.serveStream)
	hub.Handle("/remote/input", m.serveInput)
	return m
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Sessions lists current and recently ended sessions.
func (m *Manager) Sessions() []Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Session{}
	for id, s := range m.sessions {
		if !s.ended.IsZero() && time.Since(s.ended) > 20*time.Second {
			delete(m.sessions, id)
			continue
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (m *Manager) publish(kind string, s *Session) {
	b, _ := json.Marshal(s)
	m.hub.Publish(peer.Event{Kind: kind, From: s.PeerIP, Msg: b})
}

func (m *Manager) end(s *Session, state, errMsg string) {
	if s.State == "ended" || s.State == "declined" {
		return
	}
	s.State, s.Error, s.ended = state, errMsg, time.Now()
	if s.cancel != nil {
		s.cancel()
	}
}

// ----- viewer side -----

// DeviceKey returns this PC's public device key.
func (m *Manager) DeviceKey() ed25519.PublicKey { return m.key.Public().(ed25519.PublicKey) }

// Request asks a member to share their screen. With the member's access
// password (or when this PC is trusted there) it starts without anyone
// clicking Allow; remember asks the member's PC to trust this one from now on.
func (m *Manager) Request(ctx context.Context, ip netip.Addr, control bool, password string, remember bool) (string, error) {
	s := &Session{ID: newID(), PeerIP: ip.String(), PeerName: m.nameOf(ip), Control: control, State: "asking"}
	now := time.Now().Unix()
	req := request{ID: s.ID, Control: control, Key: m.DeviceKey(), Time: now,
		Sig: ed25519.Sign(m.key, signedBytes(s.ID, ip, now, control)), Password: password, Remember: remember}
	// Registered first: an automatic answer may arrive before Post returns.
	m.mu.Lock()
	m.sessions[s.ID] = s
	m.mu.Unlock()
	if err := m.hub.Post(ctx, ip, "/remote/request", req); err != nil {
		m.mu.Lock()
		delete(m.sessions, s.ID)
		m.mu.Unlock()
		return "", err
	}
	return s.ID, nil
}

func (m *Manager) serveAnswer(w http.ResponseWriter, r *http.Request, from netip.Addr) {
	var a struct {
		ID         string `json:"id"`
		Accept     bool   `json:"accept"`
		Control    bool   `json:"control"`
		Token      string `json:"token"`
		Unattended bool   `json:"unattended"`
	}
	if r.Method != http.MethodPost || peer.ReadJSON(r, &a) != nil {
		http.Error(w, "bad answer", http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	s := m.sessions[a.ID]
	if s == nil || s.Incoming || s.PeerIP != from.String() || s.State != "asking" {
		m.mu.Unlock()
		http.Error(w, "no such request", http.StatusNotFound)
		return
	}
	if a.Accept {
		s.State, s.token, s.Control, s.Unattended = "active", a.Token, s.Control && a.Control, a.Unattended
	} else {
		s.State, s.ended = "declined", time.Now()
	}
	cp := *s
	m.mu.Unlock()
	m.publish("remote-answer", &cp)
	w.WriteHeader(http.StatusNoContent)
}

// Stream copies the remote screen stream of an outgoing session to w.
func (m *Manager) Stream(ctx context.Context, id string, w io.Writer, flush func()) error {
	m.mu.Lock()
	s := m.sessions[id]
	var ip netip.Addr
	var token string
	if s != nil && !s.Incoming && s.State == "active" {
		ip, token = netip.MustParseAddr(s.PeerIP), s.token
		ctx2, cancel := context.WithCancel(ctx)
		s.cancel, ctx = cancel, ctx2
	}
	m.mu.Unlock()
	if !ip.IsValid() {
		return errors.New("no active session")
	}
	resp, err := m.hub.Stream(ctx, ip, http.MethodGet, "/remote/stream?id="+id+"&token="+token, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	buf := make([]byte, 64<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			flush()
		}
		if err != nil {
			return nil
		}
	}
}

// Input forwards viewer input to the remote PC.
func (m *Manager) Input(ctx context.Context, id string, events json.RawMessage) error {
	m.mu.Lock()
	s := m.sessions[id]
	ok := s != nil && !s.Incoming && s.State == "active" && s.Control
	var ip netip.Addr
	var token string
	if ok {
		ip, token = netip.MustParseAddr(s.PeerIP), s.token
	}
	m.mu.Unlock()
	if !ok {
		return errors.New("control is not allowed")
	}
	return m.hub.Post(ctx, ip, "/remote/input?id="+id+"&token="+token, events)
}

// ----- the side being viewed -----

func (m *Manager) serveRequest(w http.ResponseWriter, r *http.Request, from netip.Addr) {
	var req request
	if r.Method != http.MethodPost || peer.ReadJSON(r, &req) != nil || len(req.ID) != 32 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// The device key is only taken into account when the signature proves
	// the requester holds it, for this PC, recently.
	var key ed25519.PublicKey
	if len(req.Key) == ed25519.PublicKeySize && len(req.Sig) == ed25519.SignatureSize &&
		abs(time.Now().Unix()-req.Time) < 300 && m.hub.LocalIP().IsValid() &&
		ed25519.Verify(req.Key, signedBytes(req.ID, m.hub.LocalIP(), req.Time, req.Control), req.Sig) {
		key = ed25519.PublicKey(req.Key)
	}

	name := m.nameOf(from)
	auto, control := false, req.Control
	if m.policy != nil && key != nil {
		if ok, ctl := m.policy.Trusted(key); ok {
			auto, control = true, req.Control && ctl
		}
	}
	if !auto && req.Password != "" {
		if m.locked(from) {
			http.Error(w, "too many wrong passwords; try again in a few minutes", http.StatusTooManyRequests)
			return
		}
		if m.policy == nil || !m.policy.CheckPassword(req.Password) {
			m.failed(from)
			m.logf("remote desktop: %s tried a wrong access password", name)
			http.Error(w, "wrong password, or access without asking is turned off on that PC", http.StatusForbidden)
			return
		}
		auto = true
		if req.Remember && key != nil {
			m.policy.Trust(key, name, req.Control)
			m.logf("remote desktop: %s is now a trusted PC", name)
		}
	}

	s := &Session{ID: req.ID, Incoming: true, PeerIP: from.String(), PeerName: name, Control: control, State: "asking", pub: key}
	m.mu.Lock()
	if _, dup := m.sessions[req.ID]; dup {
		m.mu.Unlock()
		http.Error(w, "duplicate request", http.StatusConflict)
		return
	}
	for _, o := range m.sessions {
		if o.Incoming && (o.State == "active" || (o.State == "asking" && o.PeerIP == from.String())) {
			m.mu.Unlock()
			http.Error(w, "this PC is already in a remote session", http.StatusConflict)
			return
		}
	}
	m.sessions[s.ID] = s
	m.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
	if auto {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := m.answer(ctx, s.ID, true, control, false, true); err != nil {
				m.logf("remote desktop: %v", err)
			}
		}()
		return
	}
	cp := *s
	m.publish("remote-request", &cp)
	if m.attention != nil {
		m.attention()
	}
}

func abs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// locked reports whether a member made too many wrong guesses lately.
func (m *Manager) locked(from netip.Addr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	var recent []time.Time
	for _, t := range m.failures[from.String()] {
		if time.Since(t) < 5*time.Minute {
			recent = append(recent, t)
		}
	}
	m.failures[from.String()] = recent
	return len(recent) >= 5
}

func (m *Manager) failed(from netip.Addr) {
	m.mu.Lock()
	m.failures[from.String()] = append(m.failures[from.String()], time.Now())
	m.mu.Unlock()
}

// Answer allows (with or without control) or denies a request. With trust,
// the requesting PC may connect without asking from now on.
func (m *Manager) Answer(ctx context.Context, id string, allow, control, trust bool) error {
	return m.answer(ctx, id, allow, control, trust, false)
}

func (m *Manager) answer(ctx context.Context, id string, allow, control, trust, unattended bool) error {
	m.mu.Lock()
	s := m.sessions[id]
	if s == nil || !s.Incoming || s.State != "asking" {
		m.mu.Unlock()
		return errors.New("this request is no longer waiting")
	}
	if allow {
		s.State, s.Control, s.token, s.Unattended = "active", s.Control && control, newID(), unattended
	} else {
		s.State, s.ended = "declined", time.Now()
	}
	cp := *s
	m.mu.Unlock()
	if allow {
		how := ""
		if unattended {
			how = " (without asking)"
		}
		m.logf("remote desktop: %s can now see%s this PC%s", cp.PeerName, map[bool]string{true: " and control", false: ""}[cp.Control], how)
		if unattended {
			m.publish("remote-started", &cp)
			if m.attention != nil {
				m.attention()
			}
		}
	}
	if allow && trust && m.policy != nil && s.pub != nil {
		m.policy.Trust(s.pub, cp.PeerName, cp.Control)
	}
	return m.hub.Post(ctx, netip.MustParseAddr(cp.PeerIP), "/remote/answer",
		map[string]any{"id": id, "accept": allow, "control": cp.Control, "token": cp.token, "unattended": unattended})
}

// Stop ends a session from this side and tells the other side.
func (m *Manager) Stop(ctx context.Context, id string) {
	m.mu.Lock()
	s := m.sessions[id]
	if s == nil {
		m.mu.Unlock()
		return
	}
	m.end(s, "ended", "")
	ip := netip.MustParseAddr(s.PeerIP)
	m.mu.Unlock()
	_ = m.hub.Post(ctx, ip, "/remote/stop", map[string]any{"id": id})
}

// StopAll ends every session (when disconnecting).
func (m *Manager) StopAll() {
	m.mu.Lock()
	var ids []string
	for id, s := range m.sessions {
		if s.State == "active" || s.State == "asking" {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, id := range ids {
		m.Stop(ctx, id)
	}
}

func (m *Manager) serveStop(w http.ResponseWriter, r *http.Request, from netip.Addr) {
	var req struct {
		ID string `json:"id"`
	}
	if r.Method != http.MethodPost || peer.ReadJSON(r, &req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	s := m.sessions[req.ID]
	if s != nil && s.PeerIP == from.String() {
		m.end(s, "ended", "")
		cp := *s
		m.mu.Unlock()
		m.publish("remote-ended", &cp)
	} else {
		m.mu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
}

// session returns the active incoming session matching the request.
func (m *Manager) session(r *http.Request, from netip.Addr) *Session {
	q := r.URL.Query()
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[q.Get("id")]
	if s == nil || !s.Incoming || s.State != "active" || s.PeerIP != from.String() || s.token == "" || q.Get("token") != s.token {
		return nil
	}
	return s
}

func (m *Manager) serveInput(w http.ResponseWriter, r *http.Request, from netip.Addr) {
	s := m.session(r, from)
	if s == nil || !s.Control {
		http.Error(w, "control not allowed", http.StatusForbidden)
		return
	}
	var evs []InputEvent
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&evs); err != nil {
		http.Error(w, "bad input", http.StatusBadRequest)
		return
	}
	if err := inject(evs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ----- screen streaming -----

const (
	tileSize = 128
	fps      = 12
	quality  = 60
	maxWidth = 1920 // larger screens are scaled down
)

// Stream message types.
const (
	msgSize  = 'S' // u16 width, u16 height
	msgTile  = 'T' // u16 x, y, w, h, u32 length, JPEG
	msgFrame = 'F' // end of a frame
)

func (m *Manager) serveStream(w http.ResponseWriter, r *http.Request, from netip.Addr) {
	s := m.session(r, from)
	if s == nil {
		http.Error(w, "no active session", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	m.mu.Lock()
	if s.cancel != nil {
		s.cancel() // only one stream per session
	}
	s.cancel = cancel
	m.mu.Unlock()
	defer cancel()

	capt, err := newCapturer()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotImplemented)
		return
	}
	defer capt.Close()
	fl, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	bw := bufio.NewWriterSize(w, 256<<10)
	err = streamScreen(ctx, capt, bw, func() {
		_ = bw.Flush()
		if fl != nil {
			fl.Flush()
		}
	})
	if err != nil && ctx.Err() == nil {
		m.logf("remote desktop: %v", err)
	}
}

// Frame is a captured screen, 32-bit BGRA rows.
type Frame struct {
	W, H int
	Pix  []byte
}

type capturer interface {
	Capture() (*Frame, error)
	Close()
}

// streamScreen sends changed tiles until ctx ends or writing fails.
func streamScreen(ctx context.Context, capt capturer, w io.Writer, flush func()) error {
	var prev *Frame
	var prevPix []byte
	var enc bytes.Buffer
	tile := image.NewRGBA(image.Rect(0, 0, tileSize, tileSize))
	tick := time.NewTicker(time.Second / fps)
	defer tick.Stop()
	hdr := make([]byte, 13)
	failures := 0
	for {
		f, err := capt.Capture()
		if err != nil {
			// The screen can't be read for a moment (lock screen, UAC
			// prompt). Keep the connection and try again.
			failures++
			if failures > 50 {
				return err
			}
		} else {
			failures = 0
			f = downscale(f)
			if prev == nil || prev.W != f.W || prev.H != f.H {
				binary.BigEndian.PutUint16(hdr[1:3], uint16(f.W))
				binary.BigEndian.PutUint16(hdr[3:5], uint16(f.H))
				hdr[0] = msgSize
				if _, err := w.Write(hdr[:5]); err != nil {
					return err
				}
				prev = nil
			}
			for ty := 0; ty < f.H; ty += tileSize {
				for tx := 0; tx < f.W; tx += tileSize {
					tw, th := min(tileSize, f.W-tx), min(tileSize, f.H-ty)
					if prev != nil && sameTile(prev, f, tx, ty, tw, th) {
						continue
					}
					img := tile.SubImage(image.Rect(0, 0, tw, th)).(*image.RGBA)
					toRGBA(img, f, tx, ty, tw, th)
					enc.Reset()
					if err := jpeg.Encode(&enc, img, &jpeg.Options{Quality: quality}); err != nil {
						return err
					}
					hdr[0] = msgTile
					binary.BigEndian.PutUint16(hdr[1:3], uint16(tx))
					binary.BigEndian.PutUint16(hdr[3:5], uint16(ty))
					binary.BigEndian.PutUint16(hdr[5:7], uint16(tw))
					binary.BigEndian.PutUint16(hdr[7:9], uint16(th))
					binary.BigEndian.PutUint32(hdr[9:13], uint32(enc.Len()))
					if _, err := w.Write(hdr); err != nil {
						return err
					}
					if _, err := w.Write(enc.Bytes()); err != nil {
						return err
					}
				}
			}
			// The capturer reuses its buffer: keep a copy to compare with.
			if cap(prevPix) < len(f.Pix) {
				prevPix = make([]byte, len(f.Pix))
			}
			prevPix = prevPix[:len(f.Pix)]
			copy(prevPix, f.Pix)
			prev = &Frame{W: f.W, H: f.H, Pix: prevPix}
		}
		if _, err := w.Write([]byte{msgFrame}); err != nil {
			return err
		}
		flush()
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

func sameTile(a, b *Frame, x, y, w, h int) bool {
	stride := a.W * 4
	for row := y; row < y+h; row++ {
		off := row*stride + x*4
		if !bytes.Equal(a.Pix[off:off+w*4], b.Pix[off:off+w*4]) {
			return false
		}
	}
	return true
}

// toRGBA copies a BGRA tile into img.
func toRGBA(img *image.RGBA, f *Frame, x, y, w, h int) {
	stride := f.W * 4
	for row := 0; row < h; row++ {
		src := f.Pix[(y+row)*stride+x*4:]
		dst := img.Pix[row*img.Stride:]
		for i := 0; i < w*4; i += 4 {
			dst[i], dst[i+1], dst[i+2], dst[i+3] = src[i+2], src[i+1], src[i], 255
		}
	}
}

// downscale halves the frame until it is at most maxWidth wide.
func downscale(f *Frame) *Frame {
	for f.W > maxWidth {
		w, h := f.W/2, f.H/2
		out := &Frame{W: w, H: h, Pix: make([]byte, w*h*4)}
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				copy(out.Pix[(y*w+x)*4:(y*w+x)*4+4], f.Pix[(2*y*f.W+2*x)*4:])
			}
		}
		f = out
	}
	return f
}
