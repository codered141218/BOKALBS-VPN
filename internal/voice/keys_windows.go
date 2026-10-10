package voice

import (
	"context"
	"time"

	"github.com/codered141218/bokalbs-vpn/internal/peer"
	"golang.org/x/sys/windows"
)

var procGetAsyncKeyState = windows.NewLazySystemDLL("user32.dll").NewProc("GetAsyncKeyState")

func down(vk uint16) bool {
	if vk == 0 {
		return false
	}
	r, _, _ := procGetAsyncKeyState.Call(uintptr(vk))
	return r&0x8000 != 0
}

// WatchKeys polls the push-to-talk keys (named by Keys IDs) every 15 ms and
// reports changes to the hub, whichever window has focus. keys returns the
// current choice (team key, everyone key).
func WatchKeys(ctx context.Context, h *peer.Hub, keys func() (team, all string)) {
	var st keyState
	t := time.NewTicker(15 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			teamID, allID := keys()
			st.set(h, down(keyCode(teamID)), down(keyCode(allID)))
		}
	}
}
