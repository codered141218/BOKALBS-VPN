// Package files moves files between members: browsing and downloading from a
// member's shared folder, and sending files to a member, who first accepts
// or declines. Everything goes directly between the two apps over the VPN.
// Received files are saved in Downloads\BOKALBS VPN.
package files

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/peer"
	"github.com/codered141218/bokalbs-vpn/internal/share"
)

// Transfer is one file being received or sent.
type Transfer struct {
	ID       string  `json:"id"`
	Incoming bool    `json:"incoming"`
	Name     string  `json:"name"`
	PeerIP   string  `json:"peerIp"`
	PeerName string  `json:"peerName"`
	Size     int64   `json:"size"`
	Done     int64   `json:"done"`
	State    string  `json:"state"` // waiting, active, done, failed, declined, cancelled
	Error    string  `json:"error,omitempty"`
	Path     string  `json:"path,omitempty"` // local file
	Speed    float64 `json:"speed"`          // bytes per second

	cancel   context.CancelFunc
	token    string
	offerID  string
	started  time.Time
	lastAt   time.Time
	lastDone int64
}

// Offer is a set of files a member wants to send to this PC.
type Offer struct {
	ID       string      `json:"id"`
	From     string      `json:"from"`
	FromName string      `json:"fromName"`
	Files    []OfferFile `json:"files"`
}

// OfferFile is one offered file.
type OfferFile struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	Token string `json:"token"`
}

// Manager keeps track of transfers.
type Manager struct {
	hub       *peer.Hub
	nameOf    func(netip.Addr) string
	myName    func() string
	attention func()

	mu        sync.Mutex
	transfers []*Transfer
	offers    map[string]*Offer // incoming, by from+"/"+id
}

// New creates a manager and registers its requests on the peer channel.
func New(hub *peer.Hub, nameOf func(netip.Addr) string, myName func() string, attention func()) *Manager {
	m := &Manager{hub: hub, nameOf: nameOf, myName: myName, attention: attention, offers: map[string]*Offer{}}
	hub.Handle("/files/offer", m.serveOffer)
	hub.Handle("/files/answer", m.serveAnswer)
	hub.Handle("/files/xfer/", m.serveXfer)
	return m
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// DownloadDir is where received files go.
func DownloadDir() string {
	return filepath.Join(downloadsFolder(), "BOKALBS VPN")
}

// Transfers lists recent transfers, newest first, with fresh speeds.
func (m *Manager) Transfers() []Transfer {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	out := make([]Transfer, 0, len(m.transfers))
	for _, t := range m.transfers {
		if t.State == "active" && now.Sub(t.lastAt) >= time.Second {
			t.Speed = float64(t.Done-t.lastDone) / now.Sub(t.lastAt).Seconds()
			t.lastAt, t.lastDone = now, t.Done
		}
		out = append(out, *t)
	}
	return out
}

func (m *Manager) add(t *Transfer) {
	t.lastAt = time.Now()
	m.mu.Lock()
	m.transfers = append([]*Transfer{t}, m.transfers...)
	if len(m.transfers) > 60 {
		m.transfers = m.transfers[:60]
	}
	m.mu.Unlock()
}

func (m *Manager) find(id string) *Transfer {
	for _, t := range m.transfers {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func (m *Manager) set(t *Transfer, state, errMsg string) {
	m.mu.Lock()
	if t.State != "cancelled" || state == "cancelled" {
		t.State, t.Error = state, errMsg
		if state != "active" {
			t.Speed = 0
		}
	}
	m.mu.Unlock()
}

// ----- browsing a member's shared folder -----

// List returns a folder of a member's shared folder.
func (m *Manager) List(ctx context.Context, ip netip.Addr, dir string) (*share.Listing, error) {
	if !m.hub.IsMember(ip) {
		return nil, errors.New("not a member of the network")
	}
	u := "http://" + netip.AddrPortFrom(ip, share.Port).String() + share.ListPath + "?path=" + url.QueryEscape(dir)
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s is not sharing a folder right now", m.nameOf(ip))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return nil, fmt.Errorf("cannot open this folder: %s", strings.TrimSpace(string(msg)))
	}
	var l share.Listing
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&l); err != nil {
		return nil, err
	}
	return &l, nil
}

// Download fetches a file from a member's shared folder.
func (m *Manager) Download(ip netip.Addr, filePath string, size int64) (string, error) {
	if !m.hub.IsMember(ip) {
		return "", errors.New("not a member of the network")
	}
	clean := path.Clean("/" + filePath)
	u := "http://" + netip.AddrPortFrom(ip, share.Port).String() + (&url.URL{Path: clean}).EscapedPath()
	t := &Transfer{ID: newID(), Incoming: true, Name: path.Base(clean), PeerIP: ip.String(), PeerName: m.nameOf(ip), Size: size, State: "active"}
	m.add(t)
	go m.receive(t, func(ctx context.Context) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		return (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	})
	return t.ID, nil
}

// receive downloads into Downloads\BOKALBS VPN, as name.part first.
func (m *Manager) receive(t *Transfer, get func(context.Context) (*http.Response, error)) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.mu.Lock()
	t.cancel, t.started, t.State = cancel, time.Now(), "active"
	m.mu.Unlock()
	resp, err := get(ctx)
	if err != nil {
		m.set(t, "failed", "could not reach "+t.PeerName)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		m.set(t, "failed", t.PeerName+" answered "+resp.Status)
		return
	}
	if resp.ContentLength > 0 {
		m.mu.Lock()
		t.Size = resp.ContentLength
		m.mu.Unlock()
	}
	dir := DownloadDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		m.set(t, "failed", err.Error())
		return
	}
	final := uniquePath(dir, SafeName(t.Name))
	part := final + ".part"
	f, err := os.Create(part)
	if err != nil {
		m.set(t, "failed", err.Error())
		return
	}
	_, err = io.Copy(&counter{w: f, m: m, t: t}, resp.Body)
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err == nil && t.Size > 0 && t.Done != t.Size {
		err = fmt.Errorf("connection lost after %d of %d bytes", t.Done, t.Size)
	}
	if err != nil {
		os.Remove(part)
		if ctx.Err() != nil {
			m.set(t, "cancelled", "")
		} else {
			m.set(t, "failed", err.Error())
		}
		return
	}
	if err := os.Rename(part, final); err != nil {
		m.set(t, "failed", err.Error())
		return
	}
	m.mu.Lock()
	t.Path, t.Name = final, filepath.Base(final)
	m.mu.Unlock()
	m.set(t, "done", "")
}

type counter struct {
	w io.Writer
	m *Manager
	t *Transfer
}

func (c *counter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.m.mu.Lock()
	c.t.Done += int64(n)
	c.m.mu.Unlock()
	return n, err
}

// SafeName makes a received file name safe to create on Windows.
func SafeName(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	name = path.Base(name)
	var b strings.Builder
	for _, r := range name {
		if r < 32 || strings.ContainsRune(`<>:"/\|?*`, r) {
			b.WriteRune('_')
		} else {
			b.WriteRune(r)
		}
	}
	s := strings.Trim(b.String(), ". ")
	if s == "" {
		s = "file"
	}
	if base := strings.ToUpper(strings.TrimSuffix(s, filepath.Ext(s))); isReserved(base) {
		s = "_" + s
	}
	if len(s) > 180 {
		ext := filepath.Ext(s)
		if len(ext) > 20 {
			ext = ""
		}
		s = s[:180-len(ext)] + ext
	}
	return s
}

func isReserved(base string) bool {
	switch base {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9' {
		return true
	}
	return false
}

func uniquePath(dir, name string) string {
	p := filepath.Join(dir, name)
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; ; i++ {
		_, err1 := os.Stat(p)
		_, err2 := os.Stat(p + ".part")
		if os.IsNotExist(err1) && os.IsNotExist(err2) {
			return p
		}
		p = filepath.Join(dir, stem+" ("+strconv.Itoa(i)+")"+ext)
	}
}

// ----- sending files to a member -----

// Send offers local files to a member, who must accept them first.
func (m *Manager) Send(ctx context.Context, ip netip.Addr, paths []string) error {
	if len(paths) == 0 {
		return errors.New("no files chosen")
	}
	offer := Offer{ID: newID(), FromName: m.myName()}
	var ts []*Transfer
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			return fmt.Errorf("cannot send %q: only files can be sent", p)
		}
		t := &Transfer{ID: newID(), Name: filepath.Base(p), PeerIP: ip.String(), PeerName: m.nameOf(ip),
			Size: st.Size(), State: "waiting", Path: p, token: newID(), offerID: offer.ID, started: time.Now()}
		offer.Files = append(offer.Files, OfferFile{Name: t.Name, Size: t.Size, Token: t.token})
		ts = append(ts, t)
	}
	if err := m.hub.Post(ctx, ip, "/files/offer", offer); err != nil {
		return err
	}
	for _, t := range ts {
		m.add(t)
	}
	go m.expire(offer.ID)
	return nil
}

// expire drops offers nobody answered within 15 minutes.
func (m *Manager) expire(offerID string) {
	time.Sleep(15 * time.Minute)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.transfers {
		if t.offerID == offerID && t.State == "waiting" {
			t.State, t.Error = "failed", "not accepted in time"
		}
	}
}

func (m *Manager) serveOffer(w http.ResponseWriter, r *http.Request, from netip.Addr) {
	var o Offer
	if r.Method != http.MethodPost || peer.ReadJSON(r, &o) != nil || o.ID == "" || len(o.Files) == 0 || len(o.Files) > 500 {
		http.Error(w, "bad offer", http.StatusBadRequest)
		return
	}
	o.From = from.String()
	if name := m.nameOf(from); name != "" {
		o.FromName = name
	}
	for i := range o.Files {
		o.Files[i].Name = SafeName(o.Files[i].Name)
	}
	m.mu.Lock()
	m.offers[o.From+"/"+o.ID] = &o
	m.mu.Unlock()
	b, _ := json.Marshal(o)
	m.hub.Publish(peer.Event{Kind: "file-offer", From: o.From, Msg: b})
	if m.attention != nil {
		m.attention()
	}
	w.WriteHeader(http.StatusNoContent)
}

// Offers lists offers waiting for an answer (for windows opened later).
func (m *Manager) Offers() []Offer {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Offer{}
	for _, o := range m.offers {
		out = append(out, *o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Answer accepts or declines an offer from a member.
func (m *Manager) Answer(ctx context.Context, from netip.Addr, id string, accept bool) error {
	m.mu.Lock()
	o := m.offers[from.String()+"/"+id]
	delete(m.offers, from.String()+"/"+id)
	m.mu.Unlock()
	if o == nil {
		return errors.New("this offer is no longer available")
	}
	_ = m.hub.Post(ctx, from, "/files/answer", map[string]any{"id": id, "accept": accept})
	if !accept {
		return nil
	}
	for _, f := range o.Files {
		f := f
		t := &Transfer{ID: newID(), Incoming: true, Name: f.Name, PeerIP: o.From, PeerName: o.FromName, Size: f.Size, State: "active"}
		m.add(t)
		go m.receive(t, func(ctx context.Context) (*http.Response, error) {
			return m.hub.Stream(ctx, from, http.MethodGet, "/files/xfer/"+f.Token, nil)
		})
	}
	return nil
}

func (m *Manager) serveAnswer(w http.ResponseWriter, r *http.Request, from netip.Addr) {
	var a struct {
		ID     string `json:"id"`
		Accept bool   `json:"accept"`
	}
	if r.Method != http.MethodPost || peer.ReadJSON(r, &a) != nil {
		http.Error(w, "bad answer", http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	for _, t := range m.transfers {
		if t.offerID == a.ID && t.PeerIP == from.String() && t.State == "waiting" {
			if a.Accept {
				t.State = "accepted"
			} else {
				t.State = "declined"
			}
		}
	}
	m.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// serveXfer streams an offered file to the member it was offered to.
func (m *Manager) serveXfer(w http.ResponseWriter, r *http.Request, from netip.Addr) {
	token := strings.TrimPrefix(r.URL.Path, "/files/xfer/")
	m.mu.Lock()
	var t *Transfer
	for _, x := range m.transfers {
		if !x.Incoming && x.token == token && x.PeerIP == from.String() && (x.State == "waiting" || x.State == "accepted") {
			t = x
		}
	}
	if t != nil {
		ctx, cancel := context.WithCancel(r.Context())
		t.State, t.cancel, t.Done, t.lastAt, t.lastDone = "active", cancel, 0, time.Now(), 0
		r = r.WithContext(ctx)
	}
	m.mu.Unlock()
	if t == nil {
		http.Error(w, "no such transfer", http.StatusNotFound)
		return
	}
	f, err := os.Open(t.Path)
	if err != nil {
		m.set(t, "failed", "the file can no longer be read")
		http.Error(w, "file unavailable", http.StatusGone)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(t.Size, 10))
	_, err = io.Copy(&counter{w: w, m: m, t: t}, io.LimitReader(f, t.Size))
	switch {
	case r.Context().Err() != nil && t.Done < t.Size:
		m.set(t, "cancelled", "")
	case err != nil:
		m.set(t, "failed", "connection lost")
	default:
		m.set(t, "done", "")
	}
}

// Cancel stops a transfer.
func (m *Manager) Cancel(id string) {
	m.mu.Lock()
	t := m.find(id)
	var cancel context.CancelFunc
	if t != nil && (t.State == "active" || t.State == "waiting" || t.State == "accepted") {
		cancel = t.cancel
		t.State, t.Speed = "cancelled", 0
	}
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// LocalPath returns the file of a finished transfer.
func (m *Manager) LocalPath(id string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.find(id)
	if t == nil || t.Path == "" {
		return "", false
	}
	return t.Path, true
}

// ClearFinished removes finished transfers from the list.
func (m *Manager) ClearFinished() {
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := m.transfers[:0]
	for _, t := range m.transfers {
		if t.State == "active" || t.State == "waiting" || t.State == "accepted" {
			keep = append(keep, t)
		}
	}
	m.transfers = keep
}
