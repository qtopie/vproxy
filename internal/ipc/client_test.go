package ipc

import (
	"encoding/json"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestRequestAttach_RetrySuccess(t *testing.T) {
	origPath := SocketPath
	tmpDir := t.TempDir()
	testSock := filepath.Join(tmpDir, "test.sock")
	SocketPath = testSock
	defer func() { SocketPath = origPath }()

	var attempts int32
	started := make(chan struct{})

	// Start listener with delay to simulate daemon restarting
	go func() {
		time.Sleep(80 * time.Millisecond)
		ln, err := net.Listen("unix", testSock)
		if err != nil {
			return
		}
		defer ln.Close()
		close(started)

		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&attempts, 1)

			var req Request
			_ = json.NewDecoder(conn).Decode(&req)
			resp := AttachResponse{Success: true}
			_ = json.NewEncoder(conn).Encode(resp)
			conn.Close()
		}
	}()

	// Should succeed after retry
	err := RequestAttachWithRetry(12345, 3, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("expected retry to succeed, got error: %v", err)
	}

	<-started
	if atomic.LoadInt32(&attempts) == 0 {
		t.Errorf("expected at least 1 server request attempt, got 0")
	}
}

func TestRequestAttach_RetryExhausted(t *testing.T) {
	origPath := SocketPath
	tmpDir := t.TempDir()
	SocketPath = filepath.Join(tmpDir, "non_existent.sock")
	defer func() { SocketPath = origPath }()

	start := time.Now()
	err := RequestAttachWithRetry(12345, 2, 20*time.Millisecond)
	duration := time.Since(start)

	if err == nil {
		t.Fatal("expected error on non-existent socket, got nil")
	}
	if duration < 40*time.Millisecond {
		t.Errorf("expected at least 60ms for 2 retries (20ms + 40ms), took %v", duration)
	}
}
