package ipc

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/qtopie/vproxy/proxy/cgroup"
)

// Server represents the IPC server for vproxy.
type Server struct {
	listener net.Listener
	stopCh   chan struct{}
}

// StartServer starts the IPC server listening on SocketPath.
func StartServer() (*Server, error) {
	os.Remove(SocketPath) // Ensure socket doesn't already exist

	ln, err := net.Listen("unix", SocketPath)
	if err != nil {
		return nil, err
	}

	// Allow any local user to write to this socket to request attachment
	if err := os.Chmod(SocketPath, 0666); err != nil {
		ln.Close()
		return nil, err
	}

	s := &Server{
		listener: ln,
		stopCh:   make(chan struct{}),
	}

	go s.serve()
	return s, nil
}

func (s *Server) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return // Stopped gracefully
			default:
				continue
			}
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	cred, err := getPeerCred(conn)
	if err != nil {
		resp := AttachResponse{Success: false, Error: fmt.Sprintf("failed to retrieve peer credentials: %v", err)}
		json.NewEncoder(conn).Encode(resp)
		return
	}

	var req AttachRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}

	resp := AttachResponse{Success: true}

	// Security Validation:
	// 1. Root can attach any PID.
	// 2. A user can attach their own PID (the connecting process).
	// 3. A user can attach another PID if they own it.
	if cred.Uid != 0 && req.PID != int(cred.Pid) {
		if !isProcessOwnedBy(req.PID, cred.Uid) {
			resp.Success = false
			resp.Error = "permission denied: cannot attach process owned by another user"
			json.NewEncoder(conn).Encode(resp)
			return
		}
	}

	// Perform the privileged cgroup migration
	if err := cgroup.MoveProcessToVProxyCgroup(req.PID); err != nil {
		resp.Success = false
		resp.Error = err.Error()
	}

	json.NewEncoder(conn).Encode(resp)
}

func isProcessOwnedBy(pid int, uid uint32) bool {
	info, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		return false
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Uid == uid
	}
	return false
}

// Stop closes the IPC server and removes the socket file.
func (s *Server) Stop() {
	close(s.stopCh)
	if s.listener != nil {
		s.listener.Close()
	}
	os.Remove(SocketPath)
}
