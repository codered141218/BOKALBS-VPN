package voice

// Key is a push-to-talk key the user can pick.
type Key struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	vk   uint16 // Windows virtual-key code
}

// Keys lists the selectable push-to-talk keys. They are read without
// blocking them, so the game still sees them. Alt, Shift and Left Ctrl are
// left out on purpose: in Warcraft III, Alt+Q quits, Shift queues orders and
// Ctrl+number reassigns control groups.
var Keys = []Key{
	{"backquote", "` (tilde key)", 0xC0},
	{"capslock", "Caps Lock", 0x14},
	{"rctrl", "Right Ctrl", 0xA3},
	{"mouse4", "Mouse side button 1", 0x05},
	{"mouse5", "Mouse side button 2", 0x06},
	{"mmb", "Middle mouse button", 0x04},
	{"insert", "Insert", 0x2D},
	{"none", "(none)", 0},
}

func keyCode(id string) uint16 {
	for _, k := range Keys {
		if k.ID == id {
			return k.vk
		}
	}
	return 0
}

// ValidKey reports whether id names one of Keys.
func ValidKey(id string) bool {
	for _, k := range Keys {
		if k.ID == id {
			return true
		}
	}
	return false
}
