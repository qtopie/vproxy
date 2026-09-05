package internal

import (
	"encoding/json"
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
