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
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/app"
	"github.com/codered141218/bokalbs-vpn/internal/config"
	"github.com/codered141218/bokalbs-vpn/internal/files"
	"github.com/codered141218/bokalbs-vpn/internal/share"
	"github.com/codered141218/bokalbs-vpn/internal/voice"
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
	// A fixed address lets the window remember permissions such as the
	// microphone (for voice chat) between runs.
	ln, err := net.Listen("tcp4", "127.0.0.1:47823")
	if err != nil {
		if ln, err = net.Listen("tcp4", "127.0.0.1:0"); err != nil {
			return nil, err
		}
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
	mux.HandleFunc("/api/voice/events", u.voiceEvents)
	mux.HandleFunc("/api/voice/send", u.api(u.voiceSend))
	mux.HandleFunc("/api/voice/settings", u.api(u.voiceSettings))
	mux.HandleFunc("/api/files/list", u.api(u.filesList))
	mux.HandleFunc("/api/files/download", u.api(u.filesDownload))
	mux.HandleFunc("/api/files/pick", u.api(u.filesPick))
	mux.HandleFunc("/api/files/send", u.api(u.filesSend))
	mux.HandleFunc("/api/files/answer", u.api(u.filesAnswer))
	mux.HandleFunc("/api/files/open", u.api(u.filesOpen))
	mux.HandleFunc("/api/files/cancel", u.api(u.filesCancel))
	mux.HandleFunc("/api/files/clear", u.api(u.filesClear))
	mux.HandleFunc("/api/remote/request", u.api(u.remoteRequest))
	mux.HandleFunc("/api/remote/answer", u.api(u.remoteAnswer))
	mux.HandleFunc("/api/remote/stop", u.api(u.remoteStop))
	mux.HandleFunc("/api/remote/input", u.api(u.remoteInput))
	mux.HandleFunc("/api/remote/stream", u.remoteStream)
	mux.HandleFunc("/api/remote/access", u.api(u.remoteAccess))
	mux.HandleFunc("/api/remote/untrust", u.api(u.remoteUntrust))
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
	// The connect form only carries connection settings; keep the rest.
	cur := u.app.State().Settings
	s.ShareEnabled, s.ShareFolder = cur.ShareEnabled, cur.ShareFolder
	s.VoiceTeam, s.VoiceMode, s.VoiceTeamKey, s.VoiceAllKey = cur.VoiceTeam, cur.VoiceMode, cur.VoiceTeamKey, cur.VoiceAllKey
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

// voiceEvents streams voice setup messages and push-to-talk key changes to
// the window (Server-Sent Events). EventSource cannot set headers, so the
// token comes in the query.
func (u *UI) voiceEvents(w http.ResponseWriter, r *http.Request) {
	if r.Host != u.host || subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("t")), []byte(u.token)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	events, stop := u.app.Peer.Subscribe()
	defer stop()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	fl.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-events:
			b, _ := json.Marshal(ev)
			_, _ = w.Write([]byte("data: "))
			_, _ = w.Write(b)
			_, _ = w.Write([]byte("\n\n"))
			fl.Flush()
		case <-ping.C:
			_, _ = w.Write([]byte(": ping\n\n"))
			fl.Flush()
		}
	}
}

func (u *UI) voiceSend(r *http.Request) (any, error) {
	var req struct {
		To  string          `json:"to"`
		Msg json.RawMessage `json:"msg"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(req.To)
	if err != nil {
		return nil, errors.New("invalid address")
	}
	return nil, voice.Send(r.Context(), u.app.Peer, ip, req.Msg)
}

func (u *UI) voiceSettings(r *http.Request) (any, error) {
	var req struct {
		Team    int    `json:"team"`
		Mode    string `json:"mode"`
		TeamKey string `json:"teamKey"`
		AllKey  string `json:"allKey"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	return nil, u.app.UpdateVoice(req.Team, req.Mode, req.TeamKey, req.AllKey)
}

func (u *UI) quitHandler(r *http.Request) (any, error) {
	u.once.Do(func() { close(u.quit) })
	return nil, nil
}

// ----- files -----

func memberIP(u *UI, s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil || !u.app.IsMemberIP(ip) {
		return netip.Addr{}, errors.New("that player is not on the network")
	}
	return ip, nil
}

func (u *UI) filesList(r *http.Request) (any, error) {
	var req struct{ IP, Path string }
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	ip, err := memberIP(u, req.IP)
	if err != nil {
		return nil, err
	}
	return u.app.Files.List(r.Context(), ip, req.Path)
}

func (u *UI) filesDownload(r *http.Request) (any, error) {
	var req struct {
		IP   string `json:"ip"`
		Path string `json:"path"`
		Size int64  `json:"size"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	ip, err := memberIP(u, req.IP)
	if err != nil {
		return nil, err
	}
	id, err := u.app.Files.Download(ip, req.Path, req.Size)
	return map[string]string{"id": id}, err
}

func (u *UI) filesPick(r *http.Request) (any, error) {
	paths, err := pickFiles()
	if err != nil {
		return nil, err
	}
	return map[string][]string{"paths": paths}, nil
}

func (u *UI) filesSend(r *http.Request) (any, error) {
	var req struct {
		IP    string   `json:"ip"`
		Paths []string `json:"paths"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	ip, err := memberIP(u, req.IP)
	if err != nil {
		return nil, err
	}
	return nil, u.app.Files.Send(r.Context(), ip, req.Paths)
}

func (u *UI) filesAnswer(r *http.Request) (any, error) {
	var req struct {
		From   string `json:"from"`
		ID     string `json:"id"`
		Accept bool   `json:"accept"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(req.From)
	if err != nil {
		return nil, err
	}
	return nil, u.app.Files.Answer(r.Context(), ip, req.ID, req.Accept)
}

func (u *UI) filesOpen(r *http.Request) (any, error) {
	var req struct {
		ID     string `json:"id"`
		Reveal bool   `json:"reveal"`
		Folder bool   `json:"folder"` // open the downloads folder
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.Folder {
		dir := files.DownloadDir()
		_ = os.MkdirAll(dir, 0o755)
		return nil, openPath(dir)
	}
	p, ok := u.app.Files.LocalPath(req.ID)
	if !ok {
		return nil, errors.New("file not found")
	}
	if req.Reveal {
		return nil, revealPath(p)
	}
	return nil, openPath(p)
}

func (u *UI) filesCancel(r *http.Request) (any, error) {
	var req struct{ ID string }
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	u.app.Files.Cancel(req.ID)
	return nil, nil
}

func (u *UI) filesClear(r *http.Request) (any, error) {
	u.app.Files.ClearFinished()
	return nil, nil
}

// ----- remote desktop -----

func (u *UI) remoteRequest(r *http.Request) (any, error) {
	var req struct {
		IP       string `json:"ip"`
		Control  bool   `json:"control"`
		Password string `json:"password"`
		Remember bool   `json:"remember"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	ip, err := memberIP(u, req.IP)
	if err != nil {
		return nil, err
	}
	id, err := u.app.Remote.Request(r.Context(), ip, req.Control, req.Password, req.Remember)
	return map[string]string{"id": id}, err
}

func (u *UI) remoteAnswer(r *http.Request) (any, error) {
	var req struct {
		ID      string `json:"id"`
		Allow   bool   `json:"allow"`
		Control bool   `json:"control"`
		Trust   bool   `json:"trust"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	return nil, u.app.Remote.Answer(r.Context(), req.ID, req.Allow, req.Control, req.Trust)
}

func (u *UI) remoteStop(r *http.Request) (any, error) {
	var req struct{ ID string }
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	u.app.Remote.Stop(r.Context(), req.ID)
	return nil, nil
}

func (u *UI) remoteInput(r *http.Request) (any, error) {
	var req struct {
		ID     string          `json:"id"`
		Events json.RawMessage `json:"events"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	return nil, u.app.Remote.Input(r.Context(), req.ID, req.Events)
}

// remoteStream passes the remote screen through to the viewer window. Like
// the event stream it carries its token in the query.
func (u *UI) remoteStream(w http.ResponseWriter, r *http.Request) {
	if r.Host != u.host || subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("t")), []byte(u.token)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	fl, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	err := u.app.Remote.Stream(r.Context(), r.URL.Query().Get("id"), w, func() {
		if fl != nil {
			fl.Flush()
		}
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
}

func (u *UI) remoteAccess(r *http.Request) (any, error) {
	var req struct {
		Enabled  bool   `json:"enabled"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	return nil, u.app.SetRemoteAccess(req.Enabled, req.Password)
}

func (u *UI) remoteUntrust(r *http.Request) (any, error) {
	var req struct{ Key string }
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	return nil, u.app.Untrust(req.Key)
}
