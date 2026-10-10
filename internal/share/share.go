// Package share serves one folder, read-only, to the other members of the
// network. It listens only on the VPN address, so nobody outside the VPN
// can reach it. Friends open http://<your VPN address>:47821/ in a browser.
package share

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const Port = 47821

// ListPath answers folder listings as JSON, for the app's file browser.
const ListPath = "/.bokalbs/list"

// Listing is one folder of a shared folder.
type Listing struct {
	Owner   string  `json:"owner"`
	Path    string  `json:"path"`
	Entries []Entry `json:"entries"`
}

// Entry is a file or folder in a Listing.
type Entry struct {
	Name     string `json:"name"`
	Dir      bool   `json:"dir"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"` // unix seconds
}

// Server is a running folder share.
type Server struct {
	Folder string
	Addr   string
	srv    *http.Server
}

// Start shares folder on ip:Port. Windows needs a moment after the adapter is
// configured before the address can be used, so it retries for a while.
func Start(ctx context.Context, ip netip.Addr, folder string, name string) (*Server, error) {
	st, err := os.Stat(folder)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("shared folder %q does not exist", folder)
	}
	addr := netip.AddrPortFrom(ip, Port).String()
	var ln net.Listener
	for try := 0; ; try++ {
		ln, err = net.Listen("tcp4", addr)
		if err == nil {
			break
		}
		if try >= 30 {
			return nil, fmt.Errorf("cannot share folder on %s: %w", addr, err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	s := &Server{Folder: folder, Addr: addr}
	s.srv = &http.Server{Handler: handler(folder, name), ReadHeaderTimeout: 10 * time.Second}
	go s.srv.Serve(ln)
	return s, nil
}

func (s *Server) Close() {
	_ = s.srv.Close()
}

var page = template.Must(template.New("dir").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Name}} – {{.Path}}</title>
<style>
:root{color-scheme:light dark;--bg:#f5f6fa;--fg:#1d2230;--card:#fff;--muted:#6b7280;--accent:#2563eb;--line:#e5e7eb}
@media (prefers-color-scheme:dark){:root{--bg:#11141b;--fg:#e8eaf0;--card:#1a1f2a;--muted:#9aa3b2;--accent:#60a5fa;--line:#2a3140}}
body{margin:0;font:15px/1.5 system-ui,Segoe UI,sans-serif;background:var(--bg);color:var(--fg)}
main{max-width:900px;margin:0 auto;padding:24px 16px}
h1{font-size:20px;margin:0 0 4px} p{color:var(--muted);margin:0 0 16px}
table{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden}
td{padding:10px 14px;border-top:1px solid var(--line)} tr:first-child td{border-top:0}
td.s,td.d{color:var(--muted);white-space:nowrap;text-align:right;width:1%}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
</style></head><body><main>
<h1>📁 {{.Name}}</h1><p>{{.Path}}</p>
<table>
{{if .Parent}}<tr><td><a href="{{.Parent}}">⬆ ..</a></td><td class="s"></td><td class="d"></td></tr>{{end}}
{{range .Entries}}<tr><td><a href="{{.Href}}">{{if .Dir}}📁{{else}}📄{{end}} {{.Name}}</a></td><td class="s">{{.Size}}</td><td class="d">{{.Mod}}</td></tr>
{{else}}<tr><td>This folder is empty.</td><td></td><td></td></tr>{{end}}
</table></main></body></html>`))

type entry struct {
	Name, Href, Size, Mod string
	Dir                   bool
}

func handler(root, name string) http.Handler {
	files := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "read-only share", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == ListPath {
			listJSON(w, root, name, r.URL.Query().Get("path"))
			return
		}
		clean := path.Clean("/" + r.URL.Path)
		full := filepath.Join(root, filepath.FromSlash(clean))
		st, err := os.Stat(full)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if !st.IsDir() {
			files.ServeHTTP(w, r)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
			return
		}
		list, err := os.ReadDir(full)
		if err != nil {
			http.Error(w, "cannot read folder", http.StatusForbidden)
			return
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].IsDir() != list[j].IsDir() {
				return list[i].IsDir()
			}
			return strings.ToLower(list[i].Name()) < strings.ToLower(list[j].Name())
		})
		data := struct {
			Name, Path, Parent string
			Entries            []entry
		}{Name: name, Path: clean}
		if clean != "/" {
			data.Parent = "../"
		}
		for _, e := range list {
			info, err := e.Info()
			if err != nil {
				continue
			}
			en := entry{Name: e.Name(), Href: (&url.URL{Path: e.Name()}).String(), Dir: e.IsDir(), Mod: info.ModTime().Format("2006-01-02 15:04")}
			if e.IsDir() {
				en.Href += "/"
			} else {
				en.Size = humanSize(info.Size())
			}
			data.Entries = append(data.Entries, en)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Execute(w, data)
	})
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func listJSON(w http.ResponseWriter, root, owner, dir string) {
	clean := path.Clean("/" + dir)
	full := filepath.Join(root, filepath.FromSlash(clean))
	list, err := os.ReadDir(full)
	if err != nil {
		http.Error(w, "folder not found", http.StatusNotFound)
		return
	}
	out := Listing{Owner: owner, Path: clean, Entries: []Entry{}}
	for _, e := range list {
		info, err := e.Info()
		if err != nil {
			continue
		}
		en := Entry{Name: e.Name(), Dir: e.IsDir(), Modified: info.ModTime().Unix()}
		if !en.Dir {
			en.Size = info.Size()
		}
		out.Entries = append(out.Entries, en)
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		a, b := out.Entries[i], out.Entries[j]
		if a.Dir != b.Dir {
			return a.Dir
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
