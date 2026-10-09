// Package ui serves the application's user interface on 127.0.0.1. The
// Windows app shows it in a native window (WebView2); elsewhere it opens in
// the browser.
package ui

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/app"
	"github.com/codered141218/bokalbs-vpn/internal/config"
	"github.com/codered141218/bokalbs-vpn/internal/share"
)

//go:embed index.html
var indexHTML []byte

// UI is the local web server behind the app window.
type UI struct {
	app   *app.App
	token string
	host  string
	srv   *http.Server
	quit  chan struct{}
	once  sync.Once
}

// Start listens on a random local port.
func Start(a *app.App) (*UI, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	u := &UI{app: a, token: hex.EncodeToString(b), host: ln.Addr().String(), quit: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("/", u.index)
	mux.HandleFunc("/api/state", u.api(u.state))
	mux.HandleFunc("/api/connect", u.api(u.connect))
	mux.HandleFunc("/api/disconnect", u.api(u.disconnect))
	mux.HandleFunc("/api/share", u.api(u.updateShare))
	mux.HandleFunc("/api/pickfolder", u.api(u.pickFolder))
	mux.HandleFunc("/api/open", u.api(u.open))
	mux.HandleFunc("/api/quit", u.api(u.quitHandler))
	u.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go u.srv.Serve(ln)
	return u, nil
}

// URL is the address of the interface, including the access token.
func (u *UI) URL() string { return "http://" + u.host + "/#" + u.token }

// Quit is closed when the user presses "Quit".
func (u *UI) Quit() <-chan struct{} { return u.quit }

func (u *UI) Close() { _ = u.srv.Close() }

func (u *UI) index(w http.ResponseWriter, r *http.Request) {
	if r.Host != u.host || r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
	_, _ = w.Write(indexHTML)
}

type apiFunc func(r *http.Request) (any, error)

// api checks the access token (so other websites cannot control the app)
// and encodes the JSON response.
func (u *UI) api(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Host != u.host || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Token")), []byte(u.token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/api/state" && r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		res, err := f(r)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		if res == nil {
			res = map[string]bool{"ok": true}
		}
		_ = json.NewEncoder(w).Encode(res)
	}
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<16)).Decode(v)
}

func (u *UI) state(r *http.Request) (any, error) { return u.app.State(), nil }

func (u *UI) connect(r *http.Request) (any, error) {
	var s config.Settings
	if err := decode(r, &s); err != nil {
		return nil, err
	}
	cur := u.app.State().Settings
	s.ShareEnabled, s.ShareFolder = cur.ShareEnabled, cur.ShareFolder
	return nil, u.app.Connect(s)
}

func (u *UI) disconnect(r *http.Request) (any, error) {
	u.app.Disconnect()
	return nil, nil
}

func (u *UI) updateShare(r *http.Request) (any, error) {
	var req struct {
		Enabled bool   `json:"enabled"`
		Folder  string `json:"folder"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	return nil, u.app.UpdateShare(req.Enabled, req.Folder)
}

func (u *UI) pickFolder(r *http.Request) (any, error) {
	path, err := pickFolder()
	if err != nil {
		return nil, err
	}
	return map[string]string{"folder": path}, nil
}

func (u *UI) open(r *http.Request) (any, error) {
	var req struct {
		IP   string `json:"ip"`
		Kind string `json:"kind"` // "web" (built-in share) or "smb" (Windows file sharing)
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(req.IP)
	if err != nil || !u.app.IsMemberIP(ip) {
		return nil, errors.New("not a VPN address")
	}
	switch req.Kind {
	case "web":
		return nil, openURL("http://" + netip.AddrPortFrom(ip, share.Port).String() + "/")
	case "smb":
		return nil, openExplorer(`\\` + ip.String())
	}
	return nil, errors.New("unknown kind " + strconv.Quote(req.Kind))
}

func (u *UI) quitHandler(r *http.Request) (any, error) {
	u.once.Do(func() { close(u.quit) })
	return nil, nil
}
