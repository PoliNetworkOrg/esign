//go:build !windows

package p11

/*
#cgo linux LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long pair_rv;
typedef pair_rv (*pair_progress_fn)(const int, const char *);
typedef pair_rv (*pair_completed_fn)(const char *, const char *, const char *);
typedef pair_rv (*pair_fn)(const char *, const char *, int *, pair_progress_fn, pair_completed_fn);

static pair_rv pair_progress(const int progress, const char *message) { return 0; }
static pair_rv pair_completed(const char *pan, const char *name, const char *serial) { return 0; }

static void *pair_open(const char *path) { return dlopen(path, RTLD_NOW | RTLD_LOCAL); }
static void *pair_sym(void *lib, const char *name) { return dlsym(lib, name); }
static void pair_close(void *lib) { dlclose(lib); }

static pair_rv pair_call(void *fn, const char *pin, int *attempts) {
	return ((pair_fn)fn)(NULL, pin, attempts, pair_progress, pair_completed);
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// callPairing runs the first exported pairing function of the module at path with the full PIN.
func callPairing(path string, symbols []string, pin string) (rv uint, attempts int, err error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	lib := C.pair_open(cpath)
	if lib == nil {
		return 0, 0, fmt.Errorf("dlopen %s: %s", path, C.GoString(C.dlerror()))
	}
	defer C.pair_close(lib)
	var fn unsafe.Pointer
	for _, s := range symbols {
		cs := C.CString(s)
		fn = C.pair_sym(lib, cs)
		C.free(unsafe.Pointer(cs))
		if fn != nil {
			break
		}
	}
	if fn == nil {
		return 0, 0, errNoPairing
	}
	cpin := C.CString(pin)
	defer func() {
		C.memset(unsafe.Pointer(cpin), 0, C.size_t(len(pin)))
		C.free(unsafe.Pointer(cpin))
	}()
	n := C.int(-1)
	r := C.pair_call(fn, cpin, &n)
	return uint(r), int(n), nil
}
