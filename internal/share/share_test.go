package share

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShare(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "map.w3x"), []byte("map data"), 0o644)
	os.Mkdir(filepath.Join(root, "Replays"), 0o755)
	outside := filepath.Join(filepath.Dir(root), "secret.txt")
	os.WriteFile(outside, []byte("secret"), 0o644)
	defer os.Remove(outside)

	srv := httptest.NewServer(handler(root, "alice"))
	defer srv.Close()
	get := func(p string) (int, string) {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get("/"); code != 200 || !strings.Contains(body, "map.w3x") || !strings.Contains(body, "Replays/") {
		t.Fatalf("listing: %d %s", code, body)
	}
	if code, body := get("/map.w3x"); code != 200 || body != "map data" {
		t.Fatalf("download: %d %q", code, body)
	}
	if code, body := get("/../secret.txt"); code == 200 && body == "secret" {
		t.Fatal("escaped the shared folder")
	}
	if code, _ := get("/%2e%2e/secret.txt"); code == 200 {
		t.Fatal("escaped the shared folder (encoded)")
	}
	resp, _ := http.Post(srv.URL+"/x", "text/plain", strings.NewReader("x"))
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal("upload allowed")
	}
}
