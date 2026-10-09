// Package app ties everything together for the desktop application:
// joining or hosting a network, port forwarding and folder sharing.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/client"
	"github.com/codered141218/bokalbs-vpn/internal/config"
	"github.com/codered141218/bokalbs-vpn/internal/portmap"
	"github.com/codered141218/bokalbs-vpn/internal/server"
	"github.com/codered141218/bokalbs-vpn/internal/share"
	"github.com/codered141218/bokalbs-vpn/internal/tunnel"
)

// Hosting describes the server running on this PC.
type Hosting struct {
	Port          int             `json:"port"`
	PublicAddress string          `json:"publicAddress,omitempty"` // what friends type in
	LANAddress    string          `json:"lanAddress,omitempty"`    // for friends in the same house
	PortForward   string          `json:"portForward"`             // status of automatic port forwarding
	PortForwardOK bool            `json:"portForwardOk"`
	Warning       string          `json:"warning,omitempty"`
	Checked       bool            `json:"checked"` // router and internet address checks are done
	Members       []server.Member `json:"members"`
}

// ShareState describes this PC's shared folder.
type ShareState struct {
	Active bool   `json:"active"`
	URL    string `json:"url,omitempty"`
	Error  string `json:"error,omitempty"`
}

// State is everything the user interface shows.
type State struct {
	Version  string          `json:"version"`
	Settings config.Settings `json:"settings"`
	Running  bool            `json:"running"`
	Client   *client.Status  `json:"client,omitempty"`
	Hosting  *Hosting        `json:"hosting,omitempty"`
	Share    ShareState      `json:"share"`
	Logs     []string        `json:"logs"`
}

// App is the application state machine.
type App struct {
	version string

	// OpenDevice may be replaced in tests.
	OpenDevice func(netip.Prefix) (tunnel.Device, error)

	mu       sync.Mutex
	settings config.Settings
	cancel   context.CancelFunc
	client   *client.Client
	last     *client.Status
	srv      *server.Server
	mapping  *portmap.Mapping
	hosting  *Hosting
	share    *share.Server
	shareIP  netip.Addr
	shareErr string
	logs     []string
	logFile  io.Writer
	gen      int
}

// New creates the app and loads saved settings.
func New(version string) *App {
	a := &App{version: version, settings: config.Load(), OpenDevice: tunnel.Open}
	if err := os.MkdirAll(config.Dir(), 0o700); err == nil {
		if f, err := os.Create(filepath.Join(config.Dir(), "bokalbs-vpn.log")); err == nil {
			a.logFile = f
		}
	}
	return a
}

// Logf records a line for the log panel and the log file.
func (a *App) Logf(format string, args ...any) {
	line := time.Now().Format("15:04:05 ") + fmt.Sprintf(format, args...)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.logs = append(a.logs, line)
	if len(a.logs) > 300 {
		a.logs = a.logs[len(a.logs)-300:]
	}
	if a.logFile != nil {
		fmt.Fprintln(a.logFile, line)
	}
}

// Connect joins (and optionally hosts) a network.
func (a *App) Connect(s config.Settings) error {
	s.Nickname = strings.TrimSpace(s.Nickname)
	s.NetworkName = strings.TrimSpace(s.NetworkName)
	s.ServerAddress = strings.TrimSpace(s.ServerAddress)
	if s.Nickname == "" || s.NetworkName == "" || s.Password == "" {
		return errors.New("please fill in your nickname, the network name and the password")
	}
	if len(s.Password) < 6 {
		return errors.New("the password must be at least 6 characters")
	}
	if s.HostPort <= 0 || s.HostPort > 65535 {
		s.HostPort = server.DefaultPort
	}
	if !s.Host {
		if s.ServerAddress == "" {
			return errors.New("enter the server address your host gave you (for example 203.0.113.7:47820)")
		}
		if _, _, err := net.SplitHostPort(s.ServerAddress); err != nil {
			s.ServerAddress = net.JoinHostPort(strings.Trim(s.ServerAddress, "[]"), strconv.Itoa(server.DefaultPort))
		}
	}

	a.mu.Lock()
	if a.cancel != nil {
		a.mu.Unlock()
		return errors.New("already connected; disconnect first")
	}
	prev := a.settings
	s.ClientID = prev.ClientID
	a.settings = s
	a.gen++
	gen := a.gen
	a.last = nil
	a.mu.Unlock()
	if err := config.Save(s); err != nil {
		a.Logf("cannot save settings: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serverAddr := s.ServerAddress
	var srv *server.Server
	var hosting *Hosting
	if s.Host {
		var err error
		srv, err = server.New(server.Config{
			Listen:    ":" + strconv.Itoa(s.HostPort),
			Network:   s.NetworkName,
			Password:  s.Password,
			LeaseFile: filepath.Join(config.Dir(), "leases-"+safeName(s.NetworkName)+".json"),
			Logf:      a.Logf,
		})
		if err == nil {
			err = srv.Listen()
		}
		if err != nil {
			cancel()
			return fmt.Errorf("cannot host: %w (is another program using UDP port %d?)", err, s.HostPort)
		}
		go srv.Run(ctx)
		hosting = &Hosting{Port: s.HostPort, PortForward: "Checking your router…", LANAddress: lanAddress(s.HostPort)}
		serverAddr = "127.0.0.1:" + strconv.Itoa(s.HostPort)
	}

	c, err := client.Start(ctx, client.Config{
		Server:     serverAddr,
		Network:    s.NetworkName,
		Password:   s.Password,
		Name:       s.Nickname,
		ClientID:   s.ClientID,
		AppVersion: a.version,
		RelayOnly:  s.RelayOnly,
		OpenDevice: a.OpenDevice,
		Logf:       a.Logf,
	})
	if err != nil {
		cancel()
		return err
	}

	a.mu.Lock()
	a.cancel, a.client, a.srv, a.hosting = cancel, c, srv, hosting
	a.mu.Unlock()
	if s.Host {
		go a.setupHosting(ctx, gen, s)
		a.Logf("hosting network %q on UDP port %d", s.NetworkName, s.HostPort)
	} else {
		a.Logf("joining network %q at %s", s.NetworkName, serverAddr)
	}
	go a.watch(ctx, c)
	return nil
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

func safeName(s string) string { return unsafeChars.ReplaceAllString(s, "_") }

// setupHosting forwards the port on the router and works out the address
// friends should use.
func (a *App) setupHosting(ctx context.Context, gen int, s config.Settings) {
	var status, warning, public string
	ok := false
	upnpIP := ""
	if s.UPnP {
		m, err := portmap.Map(ctx, uint16(s.HostPort), "BOKALBS VPN")
		if err != nil {
			status = "Automatic port forwarding failed: " + err.Error() +
				fmt.Sprintf(". Forward UDP port %d to this PC in your router settings.", s.HostPort)
		} else {
			ok = true
			upnpIP = m.ExternalIP
			status = fmt.Sprintf("UDP port %d was forwarded automatically by your router.", s.HostPort)
			a.mu.Lock()
			if a.gen == gen && a.cancel != nil {
				a.mapping = m
				m = nil
			}
			a.mu.Unlock()
			if m != nil {
				m.Close()
				return
			}
		}
	} else {
		status = fmt.Sprintf("Automatic port forwarding is off. Make sure UDP port %d is forwarded to this PC.", s.HostPort)
	}
	web := publicIP(ctx)
	switch {
	case web != "":
		public = web
	case upnpIP != "":
		public = upnpIP
	}
	if upnpIP != "" {
		if ip, err := netip.ParseAddr(upnpIP); err == nil && (ip.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip)) {
			warning = "Your router's internet address (" + upnpIP + ") is not public: your provider uses CGNAT, so friends " +
				"probably cannot reach a network hosted here. Ask a friend to host, or run the server on a VPS."
		} else if web != "" && web != upnpIP {
			warning = "Your router reports a different internet address than the outside world sees; your provider may use " +
				"CGNAT. If friends cannot connect, let someone else host or use a VPS."
		}
	}
	if public != "" {
		public = net.JoinHostPort(public, strconv.Itoa(s.HostPort))
	}
	a.mu.Lock()
	if a.gen == gen && a.hosting != nil {
		a.hosting.PortForward, a.hosting.PortForwardOK, a.hosting.Warning, a.hosting.PublicAddress = status, ok, warning, public
		a.hosting.Checked = true
	}
	a.mu.Unlock()
	a.Logf("hosting: %s", status)
	if warning != "" {
		a.Logf("hosting: %s", warning)
	}
}

// publicIP asks a public service for this connection's internet address.
func publicIP(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	ip, err := netip.ParseAddr(strings.TrimSpace(string(b)))
	if err != nil || !ip.Is4() {
		return ""
	}
	return ip.String()
}

func lanAddress(port int) string {
	conn, err := net.Dial("udp4", "192.0.2.1:9") // no packet is sent
	if err != nil {
		return ""
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP
	return net.JoinHostPort(ip.String(), strconv.Itoa(port))
}

// watch keeps the shared folder in sync with the connection and cleans up
// when the client stops on its own (for example after a fatal error).
func (a *App) watch(ctx context.Context, c *client.Client) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.Done():
			st := c.Status()
			a.mu.Lock()
			if a.client == c {
				a.last = &st
			}
			a.mu.Unlock()
			if st.State == client.StateFailed {
				a.Logf("connection failed: %s", st.Message)
				a.Disconnect()
			}
			return
		case <-ctx.Done():
			return
		case <-t.C:
			a.syncShare(ctx, c.Status())
		}
	}
}

func (a *App) syncShare(ctx context.Context, st client.Status) {
	a.mu.Lock()
	want := a.settings.ShareEnabled && a.settings.ShareFolder != "" && st.State == client.StateConnected
	folder, name := a.settings.ShareFolder, a.settings.Nickname
	cur, curIP := a.share, a.shareIP
	ip, _ := netip.ParseAddr(st.IP)
	shareErr := a.shareErr
	a.mu.Unlock()

	if cur != nil && (!want || cur.Folder != folder || curIP != ip) {
		cur.Close()
		a.mu.Lock()
		a.share, a.shareIP = nil, netip.Addr{}
		a.mu.Unlock()
		cur = nil
	}
	if !want || cur != nil || shareErr != "" {
		return
	}
	s, err := share.Start(ctx, ip, folder, name)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		if ctx.Err() == nil {
			a.shareErr = err.Error()
		}
		return
	}
	if a.cancel == nil || ctx.Err() != nil {
		s.Close()
		return
	}
	a.share, a.shareIP, a.shareErr = s, ip, ""
	a.logs = append(a.logs, time.Now().Format("15:04:05 ")+"sharing "+folder+" at http://"+s.Addr+"/")
}

// UpdateShare changes the shared folder settings, also while connected.
func (a *App) UpdateShare(enabled bool, folder string) error {
	folder = strings.TrimSpace(strings.Trim(strings.TrimSpace(folder), `"`))
	if enabled {
		st, err := os.Stat(folder)
		if err != nil || !st.IsDir() {
			return fmt.Errorf("folder %q does not exist", folder)
		}
	}
	a.mu.Lock()
	a.settings.ShareEnabled, a.settings.ShareFolder = enabled, folder
	a.shareErr = ""
	s := a.settings
	a.mu.Unlock()
	return config.Save(s)
}

// Disconnect leaves the network and stops hosting.
func (a *App) Disconnect() {
	a.mu.Lock()
	cancel, c, mapping, sh := a.cancel, a.client, a.mapping, a.share
	a.cancel, a.srv, a.mapping, a.share, a.hosting = nil, nil, nil, nil, nil
	a.shareIP, a.shareErr = netip.Addr{}, ""
	a.mu.Unlock()
	if cancel == nil {
		return
	}
	if sh != nil {
		sh.Close()
	}
	if c != nil {
		select {
		case <-c.Done():
		default:
			c.Stop()
			st := c.Status()
			a.mu.Lock()
			if a.client == c {
				a.last = &st
			}
			a.mu.Unlock()
		}
	}
	cancel()
	if mapping != nil {
		mapping.Close()
	}
	a.Logf("disconnected")
}

// State returns a snapshot for the user interface.
func (a *App) State() State {
	a.mu.Lock()
	c, srv := a.client, a.srv
	st := State{
		Version:  a.version,
		Settings: a.settings,
		Running:  a.cancel != nil,
		Logs:     append([]string(nil), a.logs...),
		Share:    ShareState{Active: a.share != nil, Error: a.shareErr},
	}
	if a.share != nil {
		st.Share.URL = "http://" + a.share.Addr + "/"
	}
	if a.hosting != nil {
		h := *a.hosting
		st.Hosting = &h
	}
	last := a.last
	a.mu.Unlock()

	if st.Running && c != nil {
		cs := c.Status()
		st.Client = &cs
	} else if last != nil {
		st.Client = last
	}
	if st.Hosting != nil && srv != nil {
		st.Hosting.Members = srv.Members()
	}
	return st
}

// IsMemberIP reports whether ip belongs to the connected VPN network.
func (a *App) IsMemberIP(ip netip.Addr) bool {
	a.mu.Lock()
	c := a.client
	running := a.cancel != nil
	a.mu.Unlock()
	if !running || c == nil {
		return false
	}
	st := c.Status()
	subnet, err := netip.ParsePrefix(st.Subnet)
	return err == nil && subnet.Contains(ip)
}
