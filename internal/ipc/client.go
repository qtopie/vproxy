package ipc

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

const SocketPath = "/tmp/vproxy.sock"

type AttachRequest struct {
	PID int `json:"pid"`
}

type AttachResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// RequestAttach sends an attach request to the background vproxy daemon.
func RequestAttach(pid int) error {
	conn, err := net.DialTimeout("unix", SocketPath, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("failed to connect to vproxy daemon (is it running?): %v", err)
	}
	defer conn.Close()

	req := AttachRequest{PID: pid}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("failed to send attach request: %v", err)
	}

	var resp AttachResponse
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("failed to read attach response: %v", err)
	}

	if !resp.Success {
		return fmt.Errorf("daemon rejected attach request: %s", resp.Error)
	}

	return nil
}
