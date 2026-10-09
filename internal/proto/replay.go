package proto

const (
	windowWords = 32
	windowBits  = windowWords * 64
)

// ReplayWindow is a sliding window anti-replay filter (RFC 6479 style).
// It accepts each counter value at most once and drops values that are more
// than windowBits behind the highest one seen. The zero value is ready to use.
type ReplayWindow struct {
	last   uint64
	bitmap [windowWords]uint64
}

// Check reports whether ctr is fresh and marks it as seen.
func (w *ReplayWindow) Check(ctr uint64) bool {
	if ctr == 0 {
		return false
	}
	if ctr > w.last {
		cur := w.last / 64
		next := ctr / 64
		diff := next - cur
		if diff > windowWords {
			diff = windowWords
		}
		for i := uint64(1); i <= diff; i++ {
			w.bitmap[(cur+i)%windowWords] = 0
		}
		w.last = ctr
	} else if w.last-ctr >= windowBits-64 {
		return false
	}
	idx := (ctr / 64) % windowWords
	bit := uint64(1) << (ctr % 64)
	if w.bitmap[idx]&bit != 0 {
		return false
	}
	w.bitmap[idx] |= bit
	return true
}
