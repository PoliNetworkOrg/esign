package cie

import (
	"testing"
	"time"

	"github.com/ebfe/scard"
)

type fakeContext struct {
	names   []string
	err     error
	polled  bool
	present string
}

func (f *fakeContext) ListReaders() ([]string, error) { return f.names, f.err }

func (f *fakeContext) GetStatusChange(states []scard.ReaderState, _ time.Duration) error {
	f.polled = true
	for i := range states {
		if states[i].Reader == f.present {
			states[i].EventState = scard.StatePresent
			states[i].Atr = []byte{0x3B, 0x8F}
		}
	}
	return nil
}

// TestReadersOfNone: with no reader the states are never polled, which would panic in ebfe/scard on macOS.
func TestReadersOfNone(t *testing.T) {
	for _, ctx := range []*fakeContext{{names: []string{}}, {err: scard.ErrNoReadersAvailable}} {
		readers, err := readersOf(ctx)
		if readers != nil || err != nil || ctx.polled {
			t.Errorf("ListReaders %v, %v: got %v, %v, polled %v", ctx.names, ctx.err, readers, err, ctx.polled)
		}
	}
	readers, err := readersOf(&fakeContext{names: []string{"A", "B"}, present: "B"})
	if err != nil || len(readers) != 2 || readers[0].ATR != nil || readers[1].ATR == nil {
		t.Errorf("two readers: %+v, %v", readers, err)
	}
}
