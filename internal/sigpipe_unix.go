//go:build !windows
// +build !windows

package internal

import (
	"os/signal"
	"syscall"
)

func ignoreSIGPIPE() {
	signal.Ignore(syscall.SIGPIPE)
}
