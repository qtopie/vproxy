package internal

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
)

// RuleAction defines the action to take for a matched rule.
type RuleAction int

const (
	// ActionDirect means the connection should be established directly.
	ActionDirect RuleAction = iota
	// ActionProxy means the connection should go through the proxy.
	ActionProxy
	// ActionIntercept means the connection should be decrypted (MITM).
	ActionIntercept
	// ActionMap means the request should be mapped to a local file or another URL.
	ActionMap
)

func (ra RuleAction) String() string {
	switch ra {
	case ActionDirect:
		return "DIRECT"
	case ActionProxy:
		return "PROXY"
	case ActionIntercept:
		return "INTERCEPT"
	case ActionMap:
		return "MAP"
	default:
		return "DIRECT"
	}
}

// RuleType defines the type of a rule.
type RuleType int

const (
	RuleTypeDomain RuleType = iota
	RuleTypeProcess
	RuleTypeURL
	RuleTypePID
)

// Rule represents a single routing rule.
type Rule struct {
	Type    RuleType
	Pattern string
	PID     int // Used for RuleTypePID
	Action  RuleAction
	Target  string // Used for ActionMap (e.g., file:///path or http://url)
}

// MatchContext provides context for rule matching.
// On macOS, Process holds the full executable path returned by proc_pidpath
// (e.g. "/Applications/Telegram.app/Contents/MacOS/Telegram").
// On other platforms it is the process command name.
type MatchContext struct {
	Host    string
	Port    int
	Process string // full executable path on macOS, command name elsewhere
	PID     int    // Process ID
	URL     string // Full URL for HTTP mapping
}

// RuleManager manages a set of routing rules.
type RuleManager struct {
	rules         []Rule
	defaultAction RuleAction
	directDNS     bool
	mu            sync.RWMutex
}

// AddPIDRule adds a high-priority PID rule to the manager at runtime.
func (rm *RuleManager) AddPIDRule(pid int, action RuleAction) {
	if rm == nil {
		return
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Prepend to ensure highest priority
	rm.rules = append([]Rule{{Type: RuleTypePID, PID: pid, Action: action}}, rm.rules...)
}

// NewRuleManager creates a new RuleManager from a list of rules.
// Rules can be:
//   - "DOMAIN,example.com,PROXY"
//   - "PROCESS,Telegram,DIRECT"
//   - "INTERCEPT,example.com"
//   - "MAP,https://example.com/js/main.js,file:///tmp/main.js"
//   - "example.com,PROXY"                              (defaults to DOMAIN)
//   - "DEFAULT,DIRECT"
func NewRuleManager(ruleEntries []string) *RuleManager {
	rm := &RuleManager{
		rules:     make([]Rule, 0),
		directDNS: true,
	}
	rm.defaultAction = ActionProxy

	for _, entry := range ruleEntries {
		parts := strings.Split(entry, ",")
		if len(parts) < 2 {
			log.Printf("Router: Invalid rule format: %s. Skipping.", entry)
			continue
		}

		var ruleType RuleType = RuleTypeDomain
		var pattern, actionStr, target string
		var action RuleAction

		p0 := strings.ToUpper(strings.TrimSpace(parts[0]))
		if p0 == "MAP" && len(parts) >= 3 {
			ruleType = RuleTypeURL
			pattern = strings.TrimSpace(parts[1])
			actionStr = "MAP"
			target = strings.TrimSpace(parts[2])
		} else if p0 == "INTERCEPT" {
			ruleType = RuleTypeDomain
			pattern = strings.TrimSpace(parts[1])
			actionStr = "INTERCEPT"
		} else if len(parts) == 3 {
			pattern = strings.TrimSpace(parts[1])
			actionStr = strings.ToUpper(strings.TrimSpace(parts[2]))
		} else {
			pattern = strings.TrimSpace(parts[0])
			actionStr = strings.ToUpper(strings.TrimSpace(parts[1]))
		}

		switch actionStr {
		case "DIRECT":
			action = ActionDirect
		case "PROXY":
			action = ActionProxy
		case "INTERCEPT":
			action = ActionIntercept
		case "MAP":
			action = ActionMap
		default:
			log.Printf("Router: Unknown action '%s' in rule '%s'. Skipping.", actionStr, entry)
			continue
		}

		if p0 == "PID" {
			ruleType = RuleTypePID
			var pid int
			fmt.Sscanf(pattern, "%d", &pid)
			rm.rules = append(rm.rules, Rule{Type: ruleType, PID: pid, Action: action, Target: target})
			continue
		}

		switch p0 {
		case "DOMAIN":
			ruleType = RuleTypeDomain
		case "PROCESS":
			ruleType = RuleTypeProcess
		case "URL":
			ruleType = RuleTypeURL
		default:
			// Fallback to domain if it's not a known type
			ruleType = RuleTypeDomain
		}

		if strings.ToUpper(pattern) == "DEFAULT" || strings.ToUpper(pattern) == "FINAL" {
			rm.defaultAction = action
			continue
		}

		rm.rules = append(rm.rules, Rule{Type: ruleType, Pattern: pattern, Action: action, Target: target})
	}
	return rm
}

// SetDirectDNS sets whether DNS traffic (port 53) should be always DIRECT.
func (rm *RuleManager) SetDirectDNS(direct bool) {
	rm.directDNS = direct
}

// HasProcessMetadataRules returns true if there is at least one PROCESS or PID rule configured.
func (rm *RuleManager) HasProcessMetadataRules() bool {
	if rm == nil {
		return false
	}
	for _, rule := range rm.rules {
		if rule.Type == RuleTypeProcess || rule.Type == RuleTypePID {
			return true
		}
	}
	return false
}

// Match matches a host against the configured rules.
func (rm *RuleManager) Match(host string) (RuleAction, string) {
	return rm.MatchContext(MatchContext{Host: host})
}

// MatchURL matches a full URL against the configured rules.
func (rm *RuleManager) MatchURL(url string) (RuleAction, string) {
	return rm.MatchContext(MatchContext{URL: url})
}

// MatchContext matches a request context against the rules.
func (rm *RuleManager) MatchContext(ctx MatchContext) (RuleAction, string) {
	action, target := rm.doMatchContext(ctx)
	if IsVerbose() {
		Debugf("Router: Match %s (Port: %d, Process: %s, URL: %s) -> %s (Target: %s)", ctx.Host, ctx.Port, ctx.Process, ctx.URL, action, target)
	}
	return action, target
}

func (rm *RuleManager) doMatchContext(ctx MatchContext) (RuleAction, string) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// 0. Always direct for DNS to avoid UDP relay issues with some upstreams
	if rm.directDNS && ctx.Port == 53 {
		return ActionDirect, ""
	}

	// 1. Check for localhost and loopback IP
	if ctx.Host == "localhost" || ctx.Host == "127.0.0.1" || ctx.Host == "::1" {
		return ActionDirect, ""
	}

	// 2. Check for IP and special ranges
	if ip := net.ParseIP(ctx.Host); ip != nil {
		if isPrivateIP(ip) {
			return ActionDirect, ""
		}
	}

	// 3. Process user-defined rules
	for _, rule := range rm.rules {
		switch rule.Type {
		case RuleTypePID:
			if ctx.PID != 0 && ctx.PID == rule.PID {
				return rule.Action, rule.Target
			}
		case RuleTypeProcess:
			if ctx.Process != "" && (ctx.Process == rule.Pattern || strings.Contains(strings.ToLower(ctx.Process), strings.ToLower(rule.Pattern))) {
				return rule.Action, rule.Target
			}
		case RuleTypeDomain:
			if ctx.Host == "" {
				continue
			}
			host := ctx.Host
			if strings.HasPrefix(rule.Pattern, ".") { // e.g., .google.com
				trimmedPattern := strings.TrimPrefix(rule.Pattern, ".")
				if host == trimmedPattern || strings.HasSuffix(host, rule.Pattern) {
					return rule.Action, rule.Target
				}
			} else { // e.g., example.com
				if host == rule.Pattern || strings.HasSuffix(host, "."+rule.Pattern) {
					return rule.Action, rule.Target
				}
			}
		case RuleTypeURL:
			if ctx.URL != "" {
				// Simple prefix or contains match for URL
				if strings.HasPrefix(ctx.URL, rule.Pattern) || strings.Contains(ctx.URL, rule.Pattern) {
					return rule.Action, rule.Target
				}
			} else if ctx.Host != "" {
				// At connection level (CONNECT), we only have Host.
				// If a MAP rule's pattern contains this host, we return ActionMap
				// to trigger MITM so we can match the full URL later.
				if strings.Contains(rule.Pattern, ctx.Host) {
					return rule.Action, rule.Target
				}
			}
		}
	}
	// Default to PROXY if no specific rule matches
	return rm.defaultAction, ""
}

// isPrivateIP checks if an IP address is a private, loopback, or link-local address.
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// Private IP ranges
		// 10.0.0.0/8
		// 172.16.0.0/12
		// 192.168.0.0/16
		return ip4[0] == 10 ||
			(ip4[0] == 172 && (ip4[1] >= 16 && ip4[1] <= 31)) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	if ip6 := ip.To16(); ip6 != nil {
		// IPv6 Unique Local Address (ULA) fc00::/7
		// fc00::/7 spans fc00:: to fdff::
		return (ip6[0] & 0xfe) == 0xfc
	}
	return false
}
