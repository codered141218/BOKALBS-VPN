// Package config stores the user's settings.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

// Settings are remembered between runs.
type Settings struct {
	Nickname      string `json:"nickname"`
	ClientID      string `json:"clientId"`
	ServerAddress string `json:"serverAddress"`
	NetworkName   string `json:"networkName"`
	Password      string `json:"password,omitempty"` // only in memory / API; stored encrypted
	SavePassword  bool   `json:"savePassword"`

	Host     bool `json:"host"`     // run the network server on this PC
	HostPort int  `json:"hostPort"` // UDP port of the server
	UPnP     bool `json:"upnp"`     // ask the router to forward HostPort

	ShareEnabled bool   `json:"shareEnabled"`
	ShareFolder  string `json:"shareFolder"`

	RelayOnly bool `json:"relayOnly"`
}

type stored struct {
	Settings
	ProtectedPassword string `json:"protectedPassword,omitempty"`
}

// Dir returns the folder holding settings and logs.
func Dir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "BOKALBS-VPN")
}

func path() string { return filepath.Join(Dir(), "settings.json") }

// Defaults returns settings for a first run.
func Defaults() Settings {
	name, _ := os.Hostname()
	return Settings{Nickname: name, HostPort: 47820, UPnP: true, ClientID: newID()}
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Load reads the settings, falling back to defaults.
func Load() Settings {
	s := Defaults()
	b, err := os.ReadFile(path())
	if err != nil {
		return s
	}
	var st stored
	st.Settings = s
	if json.Unmarshal(b, &st) != nil {
		return s
	}
	out := st.Settings
	if out.ClientID == "" {
		out.ClientID = newID()
	}
	if out.HostPort == 0 {
		out.HostPort = 47820
	}
	out.Password = ""
	if st.ProtectedPassword != "" {
		if raw, err := base64.StdEncoding.DecodeString(st.ProtectedPassword); err == nil {
			if pw, err := unprotect(raw); err == nil {
				out.Password = string(pw)
			}
		}
	}
	return out
}

// Save writes the settings. The password is only kept if SavePassword is set,
// and is encrypted for the current Windows user.
func Save(s Settings) error {
	st := stored{Settings: s}
	st.Password = ""
	if s.SavePassword && s.Password != "" {
		if raw, err := protect([]byte(s.Password)); err == nil {
			st.ProtectedPassword = base64.StdEncoding.EncodeToString(raw)
		}
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	tmp := path() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path())
}
