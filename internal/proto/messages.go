package proto

import "encoding/json"

// Control message types exchanged (encrypted) between client and server.
const (
	MsgJoin     = "join"     // client -> server: who I am
	MsgConfig   = "config"   // server -> client: your address on the network
	MsgPeers    = "peers"    // server -> client: everyone else on the network
	MsgGetPeers = "getpeers" // client -> server: please resend the peer list
	MsgKeep     = "keep"     // client -> server: keepalive
	MsgKeepAck  = "keepack"  // server -> client: keepalive answer
	MsgBye      = "bye"      // client -> server: leaving
	MsgError    = "error"    // server -> client: join refused
)

// Control is the envelope of every control message.
type Control struct {
	Type string `json:"t"`

	// join
	ClientID  string   `json:"id,omitempty"`
	Name      string   `json:"name,omitempty"`
	LocalAddr []string `json:"local,omitempty"` // LAN ip:port candidates for direct connections
	AppVer    string   `json:"ver,omitempty"`

	// config
	IP     string `json:"ip,omitempty"`     // e.g. 10.77.0.5
	Prefix int    `json:"prefix,omitempty"` // e.g. 24
	Public string `json:"public,omitempty"` // client's address as seen by the server

	// peers / keepack
	PeersVersion uint64     `json:"pv,omitempty"`
	Peers        []PeerInfo `json:"peers,omitempty"`

	// error
	Error string `json:"err,omitempty"`
}

// PeerInfo describes another member of the network.
type PeerInfo struct {
	SessionID uint32   `json:"sid"`
	ClientID  string   `json:"id"`
	Name      string   `json:"name"`
	IP        string   `json:"ip"`
	Endpoints []string `json:"ep,omitempty"` // public endpoint first, then LAN candidates
	PairKey   []byte   `json:"key"`          // shared key for direct traffic with this peer
}

func (c *Control) Marshal() []byte {
	b, _ := json.Marshal(c)
	return b
}

func ParseControl(b []byte) (*Control, error) {
	var c Control
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
