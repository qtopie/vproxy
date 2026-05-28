package internal

import (
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name       string
		rules      []string
		host       string
		port       int
		process    string
		directDNS  bool
		wantAction RuleAction
	}{
		{
			name:       "Direct match exact",
			rules:      []string{"example.com,DIRECT"},
			host:       "example.com",
			wantAction: ActionDirect,
		},
		{
			name:       "Proxy match exact",
			rules:      []string{"google.com,PROXY"},
			host:       "google.com",
			wantAction: ActionProxy,
		},
		{
			name:       "Default action explicit DIRECT",
			rules:      []string{"DEFAULT,DIRECT"},
			host:       "unknown.com",
			wantAction: ActionDirect,
		},
		{
			name:       "Localhost",
			rules:      []string{"example.com,PROXY"},
			host:       "localhost",
			wantAction: ActionDirect,
		},
		{
			name:       "Private IP",
			rules:      []string{"example.com,PROXY"},
			host:       "192.168.1.1",
			wantAction: ActionDirect,
		},
		{
			name:       "DNS Direct (default)",
			rules:      []string{"google.com,PROXY"},
			host:       "8.8.8.8",
			port:       53,
			directDNS:  true,
			wantAction: ActionDirect,
		},
		{
			name:       "DNS Proxy (explicitly disabled direct)",
			rules:      []string{"DEFAULT,PROXY"},
			host:       "8.8.8.8",
			port:       53,
			directDNS:  false,
			wantAction: ActionProxy,
		},
		{
			name:       "Process match PROXY",
			rules:      []string{"PROCESS,Telegram,PROXY", "DEFAULT,DIRECT"},
			host:       "example.com",
			process:    "Telegram",
			wantAction: ActionProxy,
		},
		{
			name:       "Process match DIRECT",
			rules:      []string{"PROCESS,Safari,DIRECT", "DEFAULT,PROXY"},
			host:       "google.com",
			process:    "Safari",
			wantAction: ActionDirect,
		},
		{
			name:       "Process partial match",
			rules:      []string{"PROCESS,Slack,PROXY"},
			host:       "slack-edge.com",
			process:    "Slack-Helper",
			wantAction: ActionProxy,
		},
		{
			name:       "Domain rule still works with process",
			rules:      []string{"DOMAIN,google.com,PROXY", "DEFAULT,DIRECT"},
			host:       "google.com",
			process:    "SomeApp",
			wantAction: ActionProxy,
		},
		{
			name:       "Intercept match",
			rules:      []string{"INTERCEPT,example.com"},
			host:       "example.com",
			wantAction: ActionIntercept,
		},
		{
			name:       "Map match URL",
			rules:      []string{"MAP,https://example.com/js/main.js,file:///tmp/main.js"},
			host:       "example.com",
			wantAction: ActionMap,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := NewRuleManager(tt.rules)
			if tt.name == "DNS Proxy (explicitly disabled direct)" {
				rm.SetDirectDNS(false)
			}
			got, _ := rm.MatchContext(MatchContext{
				Host:    tt.host,
				Port:    tt.port,
				Process: tt.process,
			})
			if got != tt.wantAction {
				t.Errorf("MatchContext(host=%q, port=%d, process=%q) = %v, want %v", tt.host, tt.port, tt.process, got, tt.wantAction)
			}
		})
	}
}

func TestMatchURL(t *testing.T) {
	rules := []string{
		"MAP,https://example.com/js/main.js,file:///tmp/main.js",
		"INTERCEPT,intercept.me",
	}
	rm := NewRuleManager(rules)

	t.Run("Map exact URL", func(t *testing.T) {
		action, target := rm.MatchURL("https://example.com/js/main.js")
		if action != ActionMap || target != "file:///tmp/main.js" {
			t.Errorf("MatchURL failed: got %v, %s", action, target)
		}
	})

	t.Run("Map partial URL", func(t *testing.T) {
		action, target := rm.MatchURL("https://example.com/js/main.js?v=1")
		if action != ActionMap || target != "file:///tmp/main.js" {
			t.Errorf("MatchURL failed: got %v, %s", action, target)
		}
	})

	t.Run("Intercept host", func(t *testing.T) {
		action, _ := rm.Match("intercept.me")
		if action != ActionIntercept {
			t.Errorf("Match host failed: got %v", action)
		}
	})
}
