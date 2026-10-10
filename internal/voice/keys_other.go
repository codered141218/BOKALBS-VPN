//go:build !windows

package voice

import "context"

// WatchKeys is only implemented on Windows; elsewhere use the on-screen
// talk buttons.
func (h *Hub) WatchKeys(ctx context.Context, keys func() (team, all string)) {
	<-ctx.Done()
}
