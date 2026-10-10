//go:build !windows

package remote

import (
	"errors"
	"os"
	"sync"
)

// On other systems a test pattern can stand in for the screen
// (BOKALBS_FAKE_SCREEN=1), and input is recorded instead of performed.

type fakeCapturer struct {
	frame Frame
	n     int
}

func newCapturer() (capturer, error) {
	if os.Getenv("BOKALBS_FAKE_SCREEN") == "" {
		return nil, errors.New("remote desktop is only available on Windows")
	}
	w, h := 640, 360
	return &fakeCapturer{frame: Frame{W: w, H: h, Pix: make([]byte, w*h*4)}}, nil
}

// Capture draws a background with a square that moves every frame.
func (c *fakeCapturer) Capture() (*Frame, error) {
	f := &c.frame
	for y := 0; y < f.H; y++ {
		for x := 0; x < f.W; x++ {
			i := (y*f.W + x) * 4
			f.Pix[i], f.Pix[i+1], f.Pix[i+2] = byte(x), byte(y), 80
		}
	}
	sx := (c.n * 8) % (f.W - 40)
	for y := 100; y < 140; y++ {
		for x := sx; x < sx+40; x++ {
			i := (y*f.W + x) * 4
			f.Pix[i], f.Pix[i+1], f.Pix[i+2] = 255, 255, 255
		}
	}
	c.n++
	return f, nil
}

func (c *fakeCapturer) Close() {}

var (
	recordedMu sync.Mutex
	recorded   []InputEvent
)

func inject(evs []InputEvent) error {
	recordedMu.Lock()
	recorded = append(recorded, evs...)
	recordedMu.Unlock()
	return nil
}

// Recorded returns input received so far (for tests on non-Windows systems).
func Recorded() []InputEvent {
	recordedMu.Lock()
	defer recordedMu.Unlock()
	return append([]InputEvent(nil), recorded...)
}
