//go:build !windows

package voice

import (
	"context"

	"github.com/codered141218/bokalbs-vpn/internal/peer"
)

// WatchKeys is only implemented on Windows; elsewhere use the on-screen
// talk buttons.
func WatchKeys(ctx context.Context, h *peer.Hub, keys func() (team, all string)) {
	var st keyState
	st.set(h, false, false)
	<-ctx.Done()
}
