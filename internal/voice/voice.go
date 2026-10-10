// Package voice supports the app's voice chat.
//
// The audio itself is handled by WebRTC in the app window (Opus codec, echo
// cancellation, noise suppression) and flows directly between players over
// the VPN. This package carries the small setup messages WebRTC needs
// (offers, answers, network candidates) from one player's app to another's
// over the peer channel, and reports push-to-talk keys pressed anywhere,
// even while a game has focus.
package voice

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sync"

	"github.com/codered141218/bokalbs-vpn/internal/peer"
)

const signalPath = "/voice/signal"

// Register lets other members' apps send voice setup messages to this one.
func Register(h *peer.Hub) {
	h.Handle(signalPath, func(w http.ResponseWriter, r *http.Request, from netip.Addr) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil || !json.Valid(body) {
			http.Error(w, "bad message", http.StatusBadRequest)
			return
		}
		h.Publish(peer.Event{Kind: "signal", From: from.String(), Msg: body})
		w.WriteHeader(http.StatusNoContent)
	})
}

// Send delivers a setup message to another member's app.
func Send(ctx context.Context, h *peer.Hub, to netip.Addr, msg json.RawMessage) error {
	if !json.Valid(msg) || len(msg) > 64<<10 {
		return fmt.Errorf("invalid message")
	}
	return h.Post(ctx, to, signalPath, msg)
}

// keyState publishes push-to-talk key changes.
type keyState struct {
	mu        sync.Mutex
	team, all bool
	started   bool
}

func (k *keyState) set(h *peer.Hub, team, all bool) {
	k.mu.Lock()
	changed := !k.started || k.team != team || k.all != all
	k.team, k.all, k.started = team, all, true
	k.mu.Unlock()
	if changed {
		h.PublishSticky(peer.Event{Kind: "keys", Team: team, All: all})
	}
}
