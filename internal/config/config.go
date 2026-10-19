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

	// Voice chat.
	VoiceTeam    int    `json:"voiceTeam"`    // 1-4: who hears "talk to team"
	VoiceMode    string `json:"voiceMode"`    // "ptt" (push to talk) or "open" (open mic to team)
	VoiceTeamKey string `json:"voiceTeamKey"` // push-to-talk key for the team (voice.Keys ID)
	VoiceAllKey  string `json:"voiceAllKey"`  // push-to-talk key for everyone

	// Remote desktop: let trusted PCs, or anyone with the password, connect
	// without someone clicking Allow.
	RemoteUnattended   bool            `json:"remoteUnattended"`
	RemotePasswordHash string          `json:"-"` // stored, never sent to the window
	TrustedDevices     []TrustedDevice `json:"trustedDevices"`

	// DeviceKey is this installation's secret identity (Ed25519 seed). Other
	// PCs remember its public half when they trust this PC.
	DeviceKey []byte `json:"-"`
}

// TrustedDevice is a PC allowed to start remote desktop without asking.
type TrustedDevice struct {
	Key     string `json:"key"` // public key, base64
	Name    string `json:"name"`
	Control bool   `json:"control"` // may use mouse and keyboard (else view only)
	Added   int64  `json:"added"`   // unix seconds
}

// Normalize fills in missing voice chat settings with defaults.
func (s *Settings) Normalize() {
	if s.VoiceTeam < 1 || s.VoiceTeam > 4 {
		s.VoiceTeam = 1
	}
	if s.VoiceMode != "open" {
		s.VoiceMode = "ptt"
	}
	if s.VoiceTeamKey == "" {
		s.VoiceTeamKey = "backquote"
	}
	if s.VoiceAllKey == "" {
		s.VoiceAllKey = "capslock"
	}
}

type stored struct {
	Settings
	ProtectedPassword  string `json:"protectedPassword,omitempty"`
	ProtectedDeviceKey string `json:"protectedDeviceKey,omitempty"`
	RemotePasswordHash string `json:"remotePasswordHash,omitempty"`
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
	s := Settings{Nickname: name, HostPort: 47820, UPnP: true, ClientID: newID(), DeviceKey: newKey()}
	s.Normalize()
	return s
}

func newKey() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
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
	out.Normalize()
	out.RemotePasswordHash = st.RemotePasswordHash
	out.DeviceKey = nil
	if raw, err := base64.StdEncoding.DecodeString(st.ProtectedDeviceKey); err == nil && len(raw) > 0 {
		if key, err := unprotect(raw); err == nil && len(key) == 32 {
			out.DeviceKey = key
		}
	}
	if out.DeviceKey == nil {
		out.DeviceKey = newKey()
		// A PC that trusted the old key will ask again; nothing else changes.
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
	st := stored{Settings: s, RemotePasswordHash: s.RemotePasswordHash}
	st.Password = ""
	if len(s.DeviceKey) == 32 {
		if raw, err := protect(s.DeviceKey); err == nil {
			st.ProtectedDeviceKey = base64.StdEncoding.EncodeToString(raw)
		}
	}
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
