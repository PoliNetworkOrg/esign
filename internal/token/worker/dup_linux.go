package worker

import "golang.org/x/sys/unix"

// dup2 uses dup3: linux/arm64 has no dup2 system call.
func dup2(oldfd, newfd int) error { return unix.Dup3(oldfd, newfd, 0) }
