package p11

import (
	"fmt"
	"syscall"
	"unsafe"
)

// The callbacks are created once: Windows allows a limited number of them per process.
var (
	pairProgress  = syscall.NewCallback(func(progress, message uintptr) uintptr { return 0 })
	pairCompleted = syscall.NewCallback(func(pan, name, serial uintptr) uintptr { return 0 })
)

// callPairing runs the first exported pairing function of the module at path with the full PIN. On x64 the
// module's __stdcall is the platform calling convention.
func callPairing(path string, symbols []string, pin string) (rv uint, attempts int, err error) {
	lib, err := syscall.LoadLibrary(path)
	if err != nil {
		return 0, 0, fmt.Errorf("load %s: %w", path, err)
	}
	defer syscall.FreeLibrary(lib)
	var fn uintptr
	for _, s := range symbols {
		if fn, err = syscall.GetProcAddress(lib, s); err == nil {
			break
		}
	}
	if fn == 0 {
		return 0, 0, errNoPairing
	}
	cpin := append([]byte(pin), 0)
	defer clear(cpin)
	n := int32(-1)
	r, _, _ := syscall.SyscallN(fn, 0, uintptr(unsafe.Pointer(&cpin[0])), uintptr(unsafe.Pointer(&n)), pairProgress, pairCompleted)
	return uint(uint32(r)), int(n), nil
}
