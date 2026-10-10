package voice

import (
	"context"
	"time"

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
func (h *Hub) WatchKeys(ctx context.Context, keys func() (team, all string)) {
	t := time.NewTicker(15 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			teamID, allID := keys()
			h.SetKeys(down(keyCode(teamID)), down(keyCode(allID)))
		}
	}
}
