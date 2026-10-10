package remote

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32 = windows.NewLazySystemDLL("user32.dll")
	gdi32  = windows.NewLazySystemDLL("gdi32.dll")

	procGetDC            = user32.NewProc("GetDC")
	procReleaseDC        = user32.NewProc("ReleaseDC")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	procGetCursorInfo    = user32.NewProc("GetCursorInfo")
	procGetIconInfo      = user32.NewProc("GetIconInfo")
	procDrawIconEx       = user32.NewProc("DrawIconEx")

	procCreateCompatibleDC = gdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection   = gdi32.NewProc("CreateDIBSection")
	procSelectObject       = gdi32.NewProc("SelectObject")
	procBitBlt             = gdi32.NewProc("BitBlt")
	procDeleteObject       = gdi32.NewProc("DeleteObject")
	procDeleteDC           = gdi32.NewProc("DeleteDC")
)

const (
	smCxScreen  = 0
	smCyScreen  = 1
	srcCopy     = 0x00CC0020
	captureBlt  = 0x40000000
	cursorShown = 0x00000001
	diNormal    = 0x0003
)

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type cursorInfo struct {
	Size   uint32
	Flags  uint32
	Cursor windows.Handle
	X, Y   int32
}

type iconInfo struct {
	Icon     int32
	XHotspot uint32
	YHotspot uint32
	Mask     windows.Handle
	Color    windows.Handle
}

// gdiCapturer copies the primary screen with GDI (works on every Windows
// version, including Home editions).
type gdiCapturer struct {
	w, h   int
	screen uintptr
	mem    uintptr
	bmp    uintptr
	old    uintptr
	bits   unsafe.Pointer
	frame  Frame
}

func newCapturer() (capturer, error) {
	runtime.LockOSThread() // GDI handles belong to this thread; unlocked in Close
	c := &gdiCapturer{}
	if err := c.setup(); err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	return c, nil
}

func (c *gdiCapturer) setup() error {
	w, _, _ := procGetSystemMetrics.Call(smCxScreen)
	h, _, _ := procGetSystemMetrics.Call(smCyScreen)
	if w == 0 || h == 0 {
		return errors.New("cannot read the screen size")
	}
	c.w, c.h = int(w), int(h)
	c.screen, _, _ = procGetDC.Call(0)
	if c.screen == 0 {
		return errors.New("cannot open the screen")
	}
	c.mem, _, _ = procCreateCompatibleDC.Call(c.screen)
	bi := bitmapInfoHeader{Size: uint32(unsafe.Sizeof(bitmapInfoHeader{})), Width: int32(c.w), Height: -int32(c.h), Planes: 1, BitCount: 32}
	var bits unsafe.Pointer
	c.bmp, _, _ = procCreateDIBSection.Call(c.mem, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if c.bmp == 0 || bits == nil {
		c.release()
		return errors.New("cannot create a screen buffer")
	}
	c.bits = bits
	c.old, _, _ = procSelectObject.Call(c.mem, c.bmp)
	c.frame = Frame{W: c.w, H: c.h, Pix: unsafe.Slice((*byte)(bits), c.w*c.h*4)}
	return nil
}

func (c *gdiCapturer) release() {
	if c.mem != 0 && c.old != 0 {
		procSelectObject.Call(c.mem, c.old)
	}
	if c.bmp != 0 {
		procDeleteObject.Call(c.bmp)
	}
	if c.mem != 0 {
		procDeleteDC.Call(c.mem)
	}
	if c.screen != 0 {
		procReleaseDC.Call(0, c.screen)
	}
	*c = gdiCapturer{}
}

func (c *gdiCapturer) Capture() (*Frame, error) {
	w, _, _ := procGetSystemMetrics.Call(smCxScreen)
	h, _, _ := procGetSystemMetrics.Call(smCyScreen)
	if int(w) != c.w || int(h) != c.h { // resolution changed
		c.release()
		if err := c.setup(); err != nil {
			return nil, err
		}
	}
	r, _, _ := procBitBlt.Call(c.mem, 0, 0, uintptr(c.w), uintptr(c.h), c.screen, 0, 0, srcCopy|captureBlt)
	if r == 0 {
		return nil, errors.New("the screen cannot be captured right now")
	}
	c.drawCursor()
	return &c.frame, nil
}

// drawCursor paints the mouse pointer into the captured image.
func (c *gdiCapturer) drawCursor() {
	ci := cursorInfo{Size: uint32(unsafe.Sizeof(cursorInfo{}))}
	if r, _, _ := procGetCursorInfo.Call(uintptr(unsafe.Pointer(&ci))); r == 0 || ci.Flags&cursorShown == 0 || ci.Cursor == 0 {
		return
	}
	x, y := ci.X, ci.Y
	var ii iconInfo
	if r, _, _ := procGetIconInfo.Call(uintptr(ci.Cursor), uintptr(unsafe.Pointer(&ii))); r != 0 {
		x -= int32(ii.XHotspot)
		y -= int32(ii.YHotspot)
		if ii.Mask != 0 {
			procDeleteObject.Call(uintptr(ii.Mask))
		}
		if ii.Color != 0 {
			procDeleteObject.Call(uintptr(ii.Color))
		}
	}
	procDrawIconEx.Call(c.mem, uintptr(x), uintptr(y), uintptr(ci.Cursor), 0, 0, 0, 0, diNormal)
}

func (c *gdiCapturer) Close() {
	c.release()
	runtime.UnlockOSThread()
}

// screenSize is used to place the mouse.
func screenSize() (int, int) {
	w, _, _ := procGetSystemMetrics.Call(smCxScreen)
	h, _, _ := procGetSystemMetrics.Call(smCyScreen)
	return int(w), int(h)
}
