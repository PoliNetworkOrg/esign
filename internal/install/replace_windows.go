package install

import (
	"errors"
	"os"
)

// replace moves src over dst. Windows cannot overwrite a running executable but can rename it: an old copy is moved
// aside first and removed when no longer in use.
func replace(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	old := dst + ".old"
	_ = os.Remove(old)
	if err := os.Rename(dst, old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	_ = os.Remove(old)
	return nil
}
