// Package proto implements the BOKALBS VPN wire protocol.
//
// Every UDP datagram starts with a one byte packet type:
//
//	Hello     client -> server   [type][version][client ephemeral pub 32][mac 16]
//	Welcome   server -> client   [type][server ephemeral pub 32][session id 4][mac 16]
//	Transport client <-> server  [type][session id 4][counter 8][AEAD ciphertext]
//	Peer      client <-> client  [type][sender session id 4][counter 8][AEAD ciphertext]
//	Reset     server -> client   [type][session id 4]  ("I don't know this session")
//
// The network password is stretched with Argon2id into a pre-shared key (PSK).
// The PSK authenticates the handshake (HMAC on Hello) and is mixed into the
// session keys together with a fresh X25519 exchange, so a wrong password can
// never produce working keys and every session has forward secrecy.
//
// Encrypted payloads use ChaCha20-Poly1305. The first plaintext byte is a
// message kind (IP packet, control JSON, ping, pong).
package proto

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	Version = 1

	TypeHello     = 0x01
	TypeWelcome   = 0x02
	TypeTransport = 0x03
	TypePeer      = 0x04
	TypeReset     = 0x05

	HelloLen   = 1 + 1 + 32 + 16
	WelcomeLen = 1 + 32 + 4 + 16
	ResetLen   = 1 + 4

	// HeaderLen is the clear-text header of Transport and Peer packets.
	HeaderLen = 1 + 4 + 8
	// Overhead is the number of bytes an encrypted packet adds to its plaintext.
	Overhead = HeaderLen + chacha20poly1305.Overhead

	macLen = 16
)

// Message kinds (first byte of a decrypted payload).
const (
	KindIP      = 0x00
	KindControl = 0x01
	KindPing    = 0x02
	KindPong    = 0x03
)

var (
	ErrShort    = errors.New("packet too short")
	ErrAuth     = errors.New("authentication failed")
	ErrReplay   = errors.New("replayed or too old packet")
	ErrBadType  = errors.New("unexpected packet type")
	ErrVersion  = errors.New("unsupported protocol version")
	ErrLowOrder = errors.New("invalid public key")
)

// DerivePSK turns a network name and password into the 32 byte pre-shared key.
// It is deliberately slow (Argon2id) to make offline password guessing costly.
func DerivePSK(network, password string) []byte {
	salt := sha256.Sum256([]byte("bokalbs-vpn/v1/network/" + network))
	return argon2.IDKey([]byte(password), salt[:], 2, 32*1024, 2, 32)
}

func mac(key []byte, parts ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)[:macLen]
}

// Ephemeral is a one-time X25519 key pair used for a single handshake.
type Ephemeral struct {
	priv *ecdh.PrivateKey
}

func NewEphemeral() (*Ephemeral, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Ephemeral{priv: k}, nil
}

func (e *Ephemeral) Public() []byte { return e.priv.PublicKey().Bytes() }

// SessionKeys are the two directional keys of a client <-> server session.
type SessionKeys struct {
	ClientToServer []byte
	ServerToClient []byte
}

func deriveSession(e *Ephemeral, peerPub []byte, psk, clientPub, serverPub []byte) (*SessionKeys, error) {
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, ErrLowOrder
	}
	shared, err := e.priv.ECDH(pub)
	if err != nil {
		return nil, ErrLowOrder
	}
	info := append([]byte("bokalbs-vpn/v1/session"), clientPub...)
	info = append(info, serverPub...)
	r := hkdf.New(sha256.New, shared, psk, info)
	out := make([]byte, 64)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return &SessionKeys{ClientToServer: out[:32], ServerToClient: out[32:]}, nil
}

// BuildHello creates the first handshake packet sent by a client.
func BuildHello(psk []byte, e *Ephemeral) []byte {
	p := make([]byte, 0, HelloLen)
	p = append(p, TypeHello, Version)
	p = append(p, e.Public()...)
	return append(p, mac(psk, []byte("hello"), p)...)
}

// ParseHello verifies a Hello packet and returns the client's ephemeral public key.
func ParseHello(psk, p []byte) ([]byte, error) {
	if len(p) != HelloLen {
		return nil, ErrShort
	}
	if p[0] != TypeHello {
		return nil, ErrBadType
	}
	body, tag := p[:HelloLen-macLen], p[HelloLen-macLen:]
	if !hmac.Equal(tag, mac(psk, []byte("hello"), body)) {
		return nil, ErrAuth
	}
	if p[1] != Version {
		return nil, ErrVersion
	}
	return append([]byte(nil), p[2:34]...), nil
}

// ServerHandshake answers a verified Hello. It returns the Welcome packet and
// the session keys.
func ServerHandshake(psk, clientPub []byte, sessionID uint32) ([]byte, *SessionKeys, error) {
	e, err := NewEphemeral()
	if err != nil {
		return nil, nil, err
	}
	keys, err := deriveSession(e, clientPub, psk, clientPub, e.Public())
	if err != nil {
		return nil, nil, err
	}
	p := make([]byte, 0, WelcomeLen)
	p = append(p, TypeWelcome)
	p = append(p, e.Public()...)
	p = binary.BigEndian.AppendUint32(p, sessionID)
	p = append(p, mac(keys.ServerToClient, []byte("welcome"), p)...)
	return p, keys, nil
}

// ClientFinish verifies a Welcome packet and returns the session id and keys.
func ClientFinish(psk []byte, e *Ephemeral, p []byte) (uint32, *SessionKeys, error) {
	if len(p) != WelcomeLen {
		return 0, nil, ErrShort
	}
	if p[0] != TypeWelcome {
		return 0, nil, ErrBadType
	}
	serverPub := p[1:33]
	keys, err := deriveSession(e, serverPub, psk, e.Public(), serverPub)
	if err != nil {
		return 0, nil, err
	}
	body, tag := p[:WelcomeLen-macLen], p[WelcomeLen-macLen:]
	if !hmac.Equal(tag, mac(keys.ServerToClient, []byte("welcome"), body)) {
		return 0, nil, ErrAuth
	}
	return binary.BigEndian.Uint32(p[33:37]), keys, nil
}

// BuildReset tells a client that its session is unknown to the server.
func BuildReset(sessionID uint32) []byte {
	return binary.BigEndian.AppendUint32([]byte{TypeReset}, sessionID)
}

// PairKey derives the key two clients use to talk directly to each other.
// The server hands it out to both members of the pair.
func PairKey(serverSecret []byte, a, b string) []byte {
	if a > b {
		a, b = b, a
	}
	h := hmac.New(sha256.New, serverSecret)
	h.Write([]byte("bokalbs-vpn/v1/pair\x00" + a + "\x00" + b))
	return h.Sum(nil)
}

// Sealer encrypts packets with one key and a strictly increasing counter.
// The nonce is [sender id 4][counter 8] so two senders sharing a key (peer to
// peer) can never reuse a nonce.
type Sealer struct {
	aead  cipher.AEAD
	typ   byte
	id    uint32
	nonce uint32
	ctr   atomic.Uint64
}

// NewSealer creates a sealer. typ is TypeTransport or TypePeer, id is the
// session id written in the header, nonceID the id mixed into the nonce.
func NewSealer(key []byte, typ byte, id, nonceID uint32) (*Sealer, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: a, typ: typ, id: id, nonce: nonceID}, nil
}

// Seal encrypts kind+payload and returns the complete datagram.
func (s *Sealer) Seal(kind byte, payload []byte) []byte {
	ctr := s.ctr.Add(1)

	out := make([]byte, HeaderLen, HeaderLen+1+len(payload)+chacha20poly1305.Overhead)
	out[0] = s.typ
	binary.BigEndian.PutUint32(out[1:5], s.id)
	binary.BigEndian.PutUint64(out[5:13], ctr)
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[:4], s.nonce)
	binary.BigEndian.PutUint64(nonce[4:], ctr)
	plain := make([]byte, 0, 1+len(payload))
	plain = append(plain, kind)
	plain = append(plain, payload...)
	return s.aead.Seal(out, nonce[:], plain, out[:HeaderLen])
}

// Opener decrypts packets and rejects replays.
type Opener struct {
	aead   cipher.AEAD
	nonce  uint32
	mu     sync.Mutex
	window ReplayWindow
}

func NewOpener(key []byte, nonceID uint32) (*Opener, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &Opener{aead: a, nonce: nonceID}, nil
}

// HeaderID returns the id field of a Transport/Peer packet without verifying it.
func HeaderID(p []byte) (uint32, bool) {
	if len(p) < HeaderLen+chacha20poly1305.Overhead+1 {
		return 0, false
	}
	return binary.BigEndian.Uint32(p[1:5]), true
}

// Open authenticates and decrypts a datagram, returning the kind and payload.
func (o *Opener) Open(p []byte) (byte, []byte, error) {
	if len(p) < HeaderLen+chacha20poly1305.Overhead+1 {
		return 0, nil, ErrShort
	}
	ctr := binary.BigEndian.Uint64(p[5:13])
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[:4], o.nonce)
	binary.BigEndian.PutUint64(nonce[4:], ctr)
	plain, err := o.aead.Open(nil, nonce[:], p[HeaderLen:], p[:HeaderLen])
	if err != nil {
		return 0, nil, ErrAuth
	}
	o.mu.Lock()
	ok := o.window.Check(ctr)
	o.mu.Unlock()
	if !ok {
		return 0, nil, ErrReplay
	}
	return plain[0], plain[1:], nil
}

// RandomID returns a random non-zero uint32.
func RandomID() uint32 {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		if v := binary.BigEndian.Uint32(b[:]); v != 0 {
			return v
		}
	}
}
