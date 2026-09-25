package internal

import (
	"testing"
)

// TestBlockAction covers SPEC-BLOCK-001 ~ SPEC-BLOCK-004 unit tests.
func TestBlockAction(t *testing.T) {
	tests := []struct {
		name       string
		rules      []string
		host       string
		port       int
		process    string
		pid        int
		wantAction RuleAction
	}{
		// --- DOMAIN BLOCK ---
		{
			name:       "DOMAIN BLOCK exact match",
			rules:      []string{"DOMAIN,facebook.com,BLOCK"},
			host:       "facebook.com",
			wantAction: ActionBlock,
		},
		{
			name:       "DOMAIN BLOCK subdomain match",
			rules:      []string{"DOMAIN,facebook.com,BLOCK"},
			host:       "www.facebook.com",
			wantAction: ActionBlock,
		},
		{
			name:       "DOMAIN BLOCK deep subdomain match",
			rules:      []string{"DOMAIN,facebook.com,BLOCK"},
			host:       "static.xx.facebook.com",
			wantAction: ActionBlock,
		},
		{
			name:       "DOMAIN BLOCK no false positive on suffix overlap",
			rules:      []string{"DOMAIN,facebook.com,BLOCK", "FINAL,PROXY"},
			host:       "notfacebook.com",
			wantAction: ActionProxy,
		},

		// --- PROCESS BLOCK ---
		{
			name:       "PROCESS BLOCK exact match",
			rules:      []string{"PROCESS,curl,BLOCK"},
			host:       "google.com",
			process:    "curl",
			wantAction: ActionBlock,
		},
		{
			name:       "PROCESS BLOCK path contains match",
			rules:      []string{"PROCESS,curl,BLOCK"},
			host:       "google.com",
			process:    "/usr/bin/curl",
			wantAction: ActionBlock,
		},
		{
			name:       "PROCESS BLOCK case-insensitive",
			rules:      []string{"PROCESS,CURL,BLOCK"},
			host:       "google.com",
			process:    "curl",
			wantAction: ActionBlock,
		},
		{
			name:       "PROCESS BLOCK no match on different process",
			rules:      []string{"PROCESS,curl,BLOCK", "FINAL,PROXY"},
			host:       "google.com",
			process:    "wget",
			wantAction: ActionProxy,
		},

		// --- IP_CIDR BLOCK ---
		{
			name:       "IP_CIDR BLOCK exact hit",
			rules:      []string{"IP_CIDR,8.8.0.0/16,BLOCK"},
			host:       "8.8.8.8",
			wantAction: ActionBlock,
		},
		{
			name:       "IP_CIDR BLOCK 0.0.0.0/0 catches all public IPv4",
			rules:      []string{"IP_CIDR,0.0.0.0/0,BLOCK"},
			host:       "1.2.3.4",
			wantAction: ActionBlock,
		},
		{
			name:       "IP_CIDR BLOCK no false positive on private IP (private check precedes rules)",
			rules:      []string{"IP_CIDR,192.168.0.0/16,BLOCK"},
			host:       "192.168.1.1",
			// Private IP is caught by built-in isPrivateIP guard before user rules
			wantAction: ActionDirect,
		},
		{
			name:       "IP_CIDR ordering: inner DIRECT beats outer BLOCK",
			rules:      []string{"IP_CIDR,192.168.50.0/24,DIRECT", "IP_CIDR,0.0.0.0/0,BLOCK"},
			host:       "192.168.50.100",
			// Private IP → built-in guard returns DIRECT, user rules not reached
			wantAction: ActionDirect,
		},
		{
			name:       "IP_CIDR BLOCK public IP ordering: specific DIRECT wins over wildcard BLOCK",
			rules:      []string{"IP_CIDR,8.8.8.0/24,DIRECT", "IP_CIDR,0.0.0.0/0,BLOCK"},
			host:       "8.8.8.8",
			wantAction: ActionDirect,
		},
		{
			name:       "IP_CIDR BLOCK wildcard catches non-excepted public IP",
			rules:      []string{"IP_CIDR,8.8.8.0/24,DIRECT", "IP_CIDR,0.0.0.0/0,BLOCK"},
			host:       "1.2.3.4",
			wantAction: ActionBlock,
		},
		{
			name:       "IP_CIDR no match on domain host (CIDR only for raw IPs)",
			rules:      []string{"IP_CIDR,0.0.0.0/0,BLOCK", "FINAL,PROXY"},
			host:       "google.com",
			wantAction: ActionProxy,
		},

		// --- FINAL BLOCK ---
		{
			name:       "FINAL BLOCK catches all unmatched",
			rules:      []string{"DOMAIN,good.com,DIRECT", "FINAL,BLOCK"},
			host:       "evil.com",
			wantAction: ActionBlock,
		},
		{
			name:       "FINAL BLOCK does not affect explicitly allowed domain",
			rules:      []string{"DOMAIN,good.com,DIRECT", "FINAL,BLOCK"},
			host:       "good.com",
			wantAction: ActionDirect,
		},

		// --- COMBINED PROCESS + DOMAIN ---
		{
			name:    "PROCESS BLOCK takes priority over DOMAIN PROXY when process matches",
			rules:   []string{"PROCESS,curl,BLOCK", "DOMAIN,google.com,PROXY"},
			host:    "google.com",
			process: "curl",
			// PROCESS rule is checked first in order (rules are appended in order)
			wantAction: ActionBlock,
		},

		// --- Invalid CIDR (skipped, not panicking) ---
		{
			name:       "Invalid CIDR rule is skipped, subsequent rules work",
			rules:      []string{"IP_CIDR,not-a-cidr,BLOCK", "DOMAIN,safe.com,DIRECT"},
			host:       "safe.com",
			wantAction: ActionDirect,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rm := NewRuleManager(tc.rules)
			got, _ := rm.MatchContext(MatchContext{
				Host:    tc.host,
				Port:    tc.port,
				Process: tc.process,
				PID:     tc.pid,
			})
			if got != tc.wantAction {
				t.Errorf("got %s, want %s", got, tc.wantAction)
			}
		})
	}
}

// TestActionBlockString verifies the String() method for ActionBlock (SPEC-BLOCK-001).
func TestActionBlockString(t *testing.T) {
	if ActionBlock.String() != "BLOCK" {
		t.Errorf("ActionBlock.String() = %q, want %q", ActionBlock.String(), "BLOCK")
	}
}

// TestIPCIDRDirectAction verifies IP_CIDR,<cidr>,DIRECT routing.
func TestIPCIDRDirectAction(t *testing.T) {
	rm := NewRuleManager([]string{"IP_CIDR,8.8.0.0/16,DIRECT", "FINAL,PROXY"})
	got, _ := rm.MatchContext(MatchContext{Host: "8.8.4.4"})
	if got != ActionDirect {
		t.Errorf("expected DIRECT for 8.8.4.4 in 8.8.0.0/16, got %s", got)
	}
}

// TestFinalBlockDefault verifies FINAL,BLOCK sets default action.
func TestFinalBlockDefault(t *testing.T) {
	rm := NewRuleManager([]string{"FINAL,BLOCK"})
	got, _ := rm.MatchContext(MatchContext{Host: "anything.example.com"})
	if got != ActionBlock {
		t.Errorf("expected BLOCK (FINAL default), got %s", got)
	}
}
