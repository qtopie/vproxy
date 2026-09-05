package internal

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestConfig_BypassNodesJSON(t *testing.T) {
	cfgJSON := `{
		"upstreams": ["socks5://127.0.0.1:1080"],
		"rules": ["DEFAULT,PROXY"],
		"bypass_nodes": ["1.2.3.4", "198.51.100.0/24", "node.example.com"]
	}`

	var cfg Config
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(cfg.BypassNodes) != 3 {
		t.Fatalf("expected 3 bypass_nodes, got %d", len(cfg.BypassNodes))
	}
	if cfg.BypassNodes[0] != "1.2.3.4" || cfg.BypassNodes[1] != "198.51.100.0/24" || cfg.BypassNodes[2] != "node.example.com" {
		t.Fatalf("unexpected bypass_nodes: %v", cfg.BypassNodes)
	}
}

func TestProxyHandler_BypassNodesAndLocalRelay(t *testing.T) {
	sm := NewServerManager([]string{"socks5://127.0.0.1:1080"}, 1*time.Minute, 1*time.Second)
	rm := NewRuleManager([]string{"DEFAULT,PROXY"})
	ph := NewProxyHandler(sm, rm, 0, 0, 0, 0)

	if !ph.hasLocalUpstream() {
		t.Fatalf("expected hasLocalUpstream() to be true for socks5://127.0.0.1:1080")
	}
	if !ph.needsProcessMetadata() {
		t.Fatalf("expected needsProcessMetadata() to be true when local upstream exists")
	}

	nodes := []string{"198.51.100.1", "node.vps.com"}
	ph.SetBypassNodes(nodes)
	if len(ph.BypassNodes) != 2 || ph.BypassNodes[0] != "198.51.100.1" {
		t.Fatalf("unexpected ph.BypassNodes: %v", ph.BypassNodes)
	}
}

type mockConn struct {
	remote net.Addr
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return m.remote }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestProxyHandler_IsForwardedRelay(t *testing.T) {
	sm := NewServerManager([]string{"socks5://127.0.0.1:1080"}, 1*time.Minute, 1*time.Second)
	rm := NewRuleManager([]string{"DEFAULT,PROXY"})
	ph := NewProxyHandler(sm, rm, 0, 0, 0, 0)

	// Case 1: Windows host process with pid > 0 -> should not be forwarded relay
	hostConn := &mockConn{remote: &net.TCPAddr{IP: net.ParseIP("198.18.0.1"), Port: 54321}}
	if ph.isForwardedRelay(hostConn, false, 1234) {
		t.Fatalf("expected host process with pid>0 to not be forwarded relay")
	}

	// Case 2: FakeIP destination -> should not be forwarded relay (needs normal proxy handling)
	if ph.isForwardedRelay(hostConn, true, 0) {
		t.Fatalf("expected fakeip destination to not be forwarded relay")
	}

	// Case 3: WSL2 connection (source IP 172.28.1.5, pid == 0, not fakeip) -> forwarded relay!
	wslConn := &mockConn{remote: &net.TCPAddr{IP: net.ParseIP("172.28.1.5"), Port: 43210}}
	if !ph.isForwardedRelay(wslConn, false, 0) {
		t.Fatalf("expected WSL2 connection with pid==0 to be identified as forwarded relay")
	}

	// Case 4: No local upstream -> false
	phNoUpstream := NewProxyHandler(NewServerManager([]string{"socks5://1.2.3.4:1080"}, 1*time.Minute, 1*time.Second), rm, 0, 0, 0, 0)
	if phNoUpstream.isForwardedRelay(wslConn, false, 0) {
		t.Fatalf("expected isForwardedRelay to be false when no local upstream is configured")
	}
}

