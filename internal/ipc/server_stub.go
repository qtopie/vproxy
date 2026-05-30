//go:build !linux
// +build !linux

package ipc

import (
	"fmt"
)

// Server represents a stub IPC server for non-Linux platforms.
type Server struct {
	stopCh chan struct{}
}

// StartServer returns a nil server on non-Linux platforms.
func StartServer(repairHandler func() error) (*Server, error) {
	return nil, fmt.Errorf("IPC server is only supported on Linux")
}

// Stop is a no-op on non-Linux platforms.
func (s *Server) Stop() {
}
