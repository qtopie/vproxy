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

func TestNewRuleManager_InactiveRulesIgnored(t *testing.T) {
	rules := []string{
		"#DOMAIN,inactive1.com,PROXY",
		"# DOMAIN,inactive2.com,INTERCEPT",
		"//PROCESS,curl,PROXY",
		"DISABLED,DOMAIN,inactive3.com,BLOCK",
		"disabled,10.0.0.0/8,BLOCK",
		"active.com,PROXY",
		"FINAL,DIRECT",
	}

	rm := NewRuleManager(rules)
	if len(rm.rules) != 1 {
		t.Fatalf("Expected exactly 1 active rule parsed, got %d", len(rm.rules))
	}
	if rm.rules[0].Pattern != "active.com" || rm.rules[0].Action != ActionProxy {
		t.Fatalf("Unexpected active rule parsed: %+v", rm.rules[0])
	}
}

func TestRuleManager_InactiveRuleFallback(t *testing.T) {
	rules := []string{
		"#DOMAIN,google.com,PROXY",
		"//DOMAIN,youtube.com,PROXY",
		"DISABLED,DOMAIN,facebook.com,BLOCK",
		"active.com,PROXY",
		"FINAL,DIRECT",
	}

	rm := NewRuleManager(rules)

	// Inactive rules must not match, falling through to FINAL,DIRECT
	for _, host := range []string{"google.com", "youtube.com", "facebook.com"} {
		action, _ := rm.Match(host)
		if action != ActionDirect {
			t.Errorf("Host %s with inactive rule should fall through to DIRECT, got %v", host, action)
		}
	}

	// Active rule must match
	action, _ := rm.Match("active.com")
	if action != ActionProxy {
		t.Errorf("Host active.com should match PROXY, got %v", action)
	}
}

