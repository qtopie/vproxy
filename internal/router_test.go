package internal

import (
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name       string
		rules      string
		host       string
		wantAction RuleAction
	}{
		{
			name:       "Direct match exact",
			rules:      "example.com,DIRECT",
			host:       "example.com",
			wantAction: ActionDirect,
		},
		{
			name:       "Direct match subdomain (logic problem check)",
			rules:      "example.com,DIRECT",
			host:       "www.example.com",
			wantAction: ActionDirect, // Expecting this to match if logic is "correct"
		},
		{
			name:       "Proxy match exact",
			rules:      "google.com,PROXY",
			host:       "google.com",
			wantAction: ActionProxy,
		},
		{
			name:       "Dot prefix match exact",
			rules:      ".google.com,PROXY",
			host:       "google.com",
			wantAction: ActionProxy,
		},
		{
			name:       "Dot prefix match subdomain",
			rules:      ".google.com,PROXY",
			host:       "mail.google.com",
			wantAction: ActionProxy,
		},
		{
			name:       "Default action explicit PROXY",
			rules:      "DEFAULT,PROXY",
			host:       "unknown.com",
			wantAction: ActionProxy,
		},
		{
			name:       "Default action explicit DIRECT",
			rules:      "DEFAULT,DIRECT",
			host:       "unknown.com",
			wantAction: ActionDirect,
		},
		{
			name:       "Localhost",
			rules:      "example.com,PROXY",
			host:       "localhost",
			wantAction: ActionDirect,
		},
		{
			name:       "Private IP",
			rules:      "example.com,PROXY",
			host:       "192.168.1.1",
			wantAction: ActionDirect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := NewRuleManager([]string{tt.rules})
			got := rm.Match(tt.host)
			if got != tt.wantAction {
				t.Errorf("Match(%q) = %v, want %v (rules: %q)", tt.host, got, tt.wantAction, tt.rules)
			}
		})
	}
}
