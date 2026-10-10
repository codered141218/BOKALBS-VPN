package remote

import (
	"encoding/binary"
	"unsafe"
)

var (
	procSendInput      = user32.NewProc("SendInput")
	procMapVirtualKeyW = user32.NewProc("MapVirtualKeyW")
)

const (
	inputMouse    = 0
	inputKeyboard = 1

	mouseMove       = 0x0001
	mouseLeftDown   = 0x0002
	mouseLeftUp     = 0x0004
	mouseRightDown  = 0x0008
	mouseRightUp    = 0x0010
	mouseMiddleDown = 0x0020
	mouseMiddleUp   = 0x0040
	mouseWheel      = 0x0800
	mouseAbsolute   = 0x8000

	keyExtended = 0x0001
	keyUp       = 0x0002
)

// winInput is the INPUT structure on 64-bit Windows: a 4-byte type, 4 bytes
// of padding and a 32-byte union.
type winInput struct {
	Type uint32
	_    uint32
	Data [32]byte
}

func mouseIn(dx, dy int32, data int32, flags uint32) winInput {
	in := winInput{Type: inputMouse}
	binary.LittleEndian.PutUint32(in.Data[0:], uint32(dx))
	binary.LittleEndian.PutUint32(in.Data[4:], uint32(dy))
	binary.LittleEndian.PutUint32(in.Data[8:], uint32(data))
	binary.LittleEndian.PutUint32(in.Data[12:], flags)
	return in
}

func keyIn(vk uint16, up bool) winInput {
	in := winInput{Type: inputKeyboard}
	scan, _, _ := procMapVirtualKeyW.Call(uintptr(vk), 0)
	var flags uint32
	if up {
		flags |= keyUp
	}
	if extendedKey(vk) {
		flags |= keyExtended
	}
	binary.LittleEndian.PutUint16(in.Data[0:], vk)
	binary.LittleEndian.PutUint16(in.Data[2:], uint16(scan))
	binary.LittleEndian.PutUint32(in.Data[4:], flags)
	return in
}

func extendedKey(vk uint16) bool {
	switch vk {
	case 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // page up/down, end, home, arrows
		0x2D, 0x2E, // insert, delete
		0x5B, 0x5C, 0x5D, // windows keys, menu
		0x6F,       // numpad divide
		0xA3, 0xA5, // right ctrl, right alt
		0x90: // num lock
		return true
	}
	return false
}

func inject(evs []InputEvent) error {
	w, h := screenSize()
	if w < 2 || h < 2 {
		return nil
	}
	var ins []winInput
	for _, e := range evs {
		ax := int32(clamp01(e.X) * 65535)
		ay := int32(clamp01(e.Y) * 65535)
		switch e.T {
		case "move":
			ins = append(ins, mouseIn(ax, ay, 0, mouseMove|mouseAbsolute))
		case "down", "up":
			flags := map[[2]int]uint32{
				{0, 0}: mouseLeftDown, {0, 1}: mouseLeftUp,
				{1, 0}: mouseMiddleDown, {1, 1}: mouseMiddleUp,
				{2, 0}: mouseRightDown, {2, 1}: mouseRightUp,
			}[[2]int{e.B, map[bool]int{false: 0, true: 1}[e.T == "up"]}]
			if flags != 0 {
				ins = append(ins, mouseIn(ax, ay, 0, flags|mouseMove|mouseAbsolute))
			}
		case "wheel":
			ins = append(ins, mouseIn(0, 0, int32(e.D), mouseWheel))
		case "key":
			if e.K != 0 {
				ins = append(ins, keyIn(e.K, e.Up))
			}
		}
	}
	if len(ins) == 0 {
		return nil
	}
	procSendInput.Call(uintptr(len(ins)), uintptr(unsafe.Pointer(&ins[0])), unsafe.Sizeof(winInput{}))
	return nil
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
