//go:build linux
// +build linux

package tproxy

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// ── ListenUDP4Direct ─────────────────────────────────────────────────────────

func TestListenUDP4Direct_BindAndClose(t *testing.T) {
	conn, err := ListenUDP4Direct(0) // port 0 = OS-assigned
	if err != nil {
		t.Fatalf("ListenUDP4Direct(0): %v", err)
	}
	defer conn.Close()

	addr := conn.LocalAddr().(*net.UDPAddr)
	if addr.Port == 0 {
		t.Error("expected non-zero port assigned by OS")
	}
	if !addr.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("expected IP 127.0.0.1, got %v", addr.IP)
	}
}

func TestListenUDP4Direct_PortConflict(t *testing.T) {
	// Bind a port, then try binding the same port again — should fail.
	conn1, err := ListenUDP4Direct(0)
	if err != nil {
		t.Fatalf("first bind: %v", err)
	}
	defer conn1.Close()

	port := conn1.LocalAddr().(*net.UDPAddr).Port
	_, err = ListenUDP4Direct(port)
	if err == nil {
		t.Errorf("expected error when binding already-used port %d, got nil", port)
	}
}

// ── ListenUDP6Direct ─────────────────────────────────────────────────────────

func TestListenUDP6Direct_BindAndClose(t *testing.T) {
	conn, err := ListenUDP6Direct(0)
	if err != nil {
		t.Fatalf("ListenUDP6Direct(0): %v", err)
	}
	defer conn.Close()

	addr := conn.LocalAddr().(*net.UDPAddr)
	if addr.Port == 0 {
		t.Error("expected non-zero port assigned by OS")
	}
	// Should be bound to ::1
	if !addr.IP.Equal(net.ParseIP("::1")) {
		t.Errorf("expected IP ::1, got %v", addr.IP)
	}
}

func TestListenUDP6Direct_IPv6Only(t *testing.T) {
	// IPv4 and IPv6 listeners on the same port should NOT conflict because
	// ListenUDP6Direct sets IPV6_V6ONLY = 1.
	conn4, err := ListenUDP4Direct(0)
	if err != nil {
		t.Fatalf("IPv4 bind: %v", err)
	}
	defer conn4.Close()
	port := conn4.LocalAddr().(*net.UDPAddr).Port

	conn6, err := ListenUDP6Direct(port)
	if err != nil {
		t.Fatalf("IPv6 bind on same port %d failed (IPV6_V6ONLY should allow this): %v", port, err)
	}
	conn6.Close()
}

// ── GetOriginalDstEBPF fallback ───────────────────────────────────────────────

func TestGetOriginalDstEBPF_NilMap_Fallback(t *testing.T) {
	// With a nil map, GetOriginalDstEBPF must fall through to GetOriginalDst.
	// GetOriginalDst will fail on a plain loopback connection (no REDIRECT/TPROXY),
	// but the important thing is it doesn't panic and returns an error cleanly.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	connCh := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		connCh <- c
	}()

	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	server := <-connCh
	defer server.Close()

	// Nil map → skips eBPF lookup → tries SO_ORIGINAL_DST getsockopt.
	// On a plain socket (no iptables REDIRECT) this returns an error — that's expected.
	_, err = GetOriginalDstEBPF(server, nil)
	// We don't assert success here; we only assert it doesn't panic.
	t.Logf("GetOriginalDstEBPF with nil map returned (as expected): %v", err)
}

// ── GetOriginalDst IPv4 ───────────────────────────────────────────────────────

func TestGetOriginalDst_NotTCPConn(t *testing.T) {
	// Passing a non-TCPConn should return a descriptive error, not panic.
	fakeConn := &fakeConn{}
	_, err := GetOriginalDst(fakeConn)
	if err == nil {
		t.Error("expected error for non-TCPConn, got nil")
	}
}

// fakeConn is a minimal net.Conn that is not a *net.TCPConn.
type fakeConn struct{}

func (f *fakeConn) Read(_ []byte) (int, error)                { return 0, fmt.Errorf("fake") }
func (f *fakeConn) Write(_ []byte) (int, error)               { return 0, fmt.Errorf("fake") }
func (f *fakeConn) Close() error                              { return nil }
func (f *fakeConn) LocalAddr() net.Addr                       { return &net.TCPAddr{} }
func (f *fakeConn) RemoteAddr() net.Addr                      { return &net.TCPAddr{} }
func (f *fakeConn) SetDeadline(_ time.Time) error             { return nil }
func (f *fakeConn) SetReadDeadline(_ time.Time) error         { return nil }
func (f *fakeConn) SetWriteDeadline(_ time.Time) error        { return nil }
