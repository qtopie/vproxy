package ipc

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

const SocketPath = "/tmp/vproxy.sock"

type RequestType string

const (
	TypeAttach RequestType = "attach"
	TypeStatus RequestType = "status"
	TypeRepair RequestType = "repair"
)

type Request struct {
	Type RequestType     `json:"type"`
	Data json.RawMessage `json:"data"`
}

type AttachRequest struct {
	PID int `json:"pid"`
}

type AttachResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type StatusResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Version string `json:"version"`
	Uptime  string `json:"uptime"`
}

// RequestAttach sends an attach request to the background vproxy daemon.
func RequestAttach(pid int) error {
	conn, err := net.DialTimeout("unix", SocketPath, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("failed to connect to vproxy daemon (is it running?): %v", err)
	}
	defer conn.Close()

	attachData, _ := json.Marshal(AttachRequest{PID: pid})
	req := Request{
		Type: TypeAttach,
		Data: attachData,
	}
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

// RequestStatus sends a status request to the background vproxy daemon.
func RequestStatus() (*StatusResponse, error) {
	conn, err := net.DialTimeout("unix", SocketPath, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to vproxy daemon (is it running?): %v", err)
	}
	defer conn.Close()

	req := Request{
		Type: TypeStatus,
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send status request: %v", err)
	}

	var resp StatusResponse
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to read status response: %v", err)
	}

	return &resp, nil
}

// RequestRepair sends a repair request to the background vproxy daemon.
func RequestRepair() error {
	conn, err := net.DialTimeout("unix", SocketPath, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("failed to connect to vproxy daemon (is it running?): %v", err)
	}
	defer conn.Close()

	req := Request{
		Type: TypeRepair,
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("failed to send repair request: %v", err)
	}

	var resp AttachResponse // Reuse AttachResponse for simple Success/Error
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // Healing might take a moment
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("failed to read repair response: %v", err)
	}

	if !resp.Success {
		return fmt.Errorf("daemon failed to self-heal: %s", resp.Error)
	}

	return nil
}

