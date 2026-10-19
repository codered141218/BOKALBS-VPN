package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/config"
	"golang.org/x/crypto/argon2"
)

// Remote desktop access without asking: an access password and a list of
// trusted PCs, kept in the settings. Implements remote.Policy.
type remotePolicy struct{ a *App }

func (p remotePolicy) Trusted(key ed25519.PublicKey) (bool, bool) {
	k := base64.StdEncoding.EncodeToString(key)
	p.a.mu.Lock()
	defer p.a.mu.Unlock()
	for _, d := range p.a.settings.TrustedDevices {
		if d.Key == k {
			return true, d.Control
		}
	}
	return false, false
}

func (p remotePolicy) CheckPassword(pw string) bool {
	p.a.mu.Lock()
	on, hash := p.a.settings.RemoteUnattended, p.a.settings.RemotePasswordHash
	p.a.mu.Unlock()
	return on && hash != "" && checkPassword(hash, pw)
}

func (p remotePolicy) Trust(key ed25519.PublicKey, name string, control bool) {
	k := base64.StdEncoding.EncodeToString(key)
	p.a.mu.Lock()
	list := p.a.settings.TrustedDevices[:0:0]
	for _, d := range p.a.settings.TrustedDevices {
		if d.Key != k {
			list = append(list, d)
		}
	}
	p.a.settings.TrustedDevices = append(list, config.TrustedDevice{Key: k, Name: name, Control: control, Added: time.Now().Unix()})
	s := p.a.settings
	p.a.mu.Unlock()
	if err := config.Save(s); err != nil {
		p.a.Logf("cannot save trusted PCs: %v", err)
	}
}

// Argon2id makes guessing the stored password slow even if the settings
// file is copied.
func hashPassword(pw string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	sum := argon2.IDKey([]byte(pw), salt, 2, 64*1024, 2, 32)
	return "argon2id$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(sum)
}

func checkPassword(stored, pw string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[1])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, 2, 64*1024, 2, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// SetRemoteAccess turns access without asking on or off. A non-empty
// password replaces the current one.
func (a *App) SetRemoteAccess(enabled bool, password string) error {
	if password != "" && len(password) < 8 {
		return errors.New("the access password must be at least 8 characters")
	}
	var hash string
	if password != "" {
		hash = hashPassword(password)
	}
	a.mu.Lock()
	if hash != "" {
		a.settings.RemotePasswordHash = hash
	}
	if enabled && a.settings.RemotePasswordHash == "" && len(a.settings.TrustedDevices) == 0 {
		a.mu.Unlock()
		return errors.New("set an access password first")
	}
	a.settings.RemoteUnattended = enabled
	s := a.settings
	a.mu.Unlock()
	if enabled {
		a.Logf("remote desktop: access without asking is on")
	} else {
		a.Logf("remote desktop: access without asking is off")
	}
	return config.Save(s)
}

// Untrust removes a trusted PC.
func (a *App) Untrust(key string) error {
	a.mu.Lock()
	list := a.settings.TrustedDevices[:0:0]
	for _, d := range a.settings.TrustedDevices {
		if d.Key != key {
			list = append(list, d)
		}
	}
	a.settings.TrustedDevices = list
	s := a.settings
	a.mu.Unlock()
	return config.Save(s)
}

// Fingerprint is a short, readable form of a device key, for showing which
// PC is which.
func Fingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	s := strings.ToUpper(base64.RawStdEncoding.EncodeToString(sum[:6]))
	s = strings.NewReplacer("+", "X", "/", "Y").Replace(s)
	return s[:4] + "-" + s[4:8]
}
