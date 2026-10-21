package cie

import "testing"

// SetServiceNeedsReader sets until the end of the test whether the smart-card service runs only with a reader
// connected, as on Windows.
func SetServiceNeedsReader(t testing.TB, v bool) {
	old := serviceNeedsReader
	serviceNeedsReader = v
	t.Cleanup(func() { serviceNeedsReader = old })
}
