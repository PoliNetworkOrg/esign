//go:build !windows

package install

import "os"

func replace(src, dst string) error { return os.Rename(src, dst) }
