package server

import "runtime"

func osName() string { return runtime.GOOS + "/" + runtime.GOARCH }
