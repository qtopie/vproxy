package internal

import (
	"log"
	"net"
	"strings"
)

// RuleAction defines the action to take for a matched rule.
type RuleAction int

const (
	// ActionDirect means the connection should be established directly.
	ActionDirect RuleAction = iota
	// ActionProxy means the connection should go through the proxy.
	ActionProxy
)

func (ra RuleAction) String() string {
	switch ra {
	case ActionDirect:
		return "DIRECT"
	case ActionProxy:
		return "PROXY"
	default:
		return "DIRECT"
	}
}

// Rule represents a single routing rule.
type Rule struct {
	Pattern string
	Action  RuleAction
}

// RuleManager manages a set of routing rules.
type RuleManager struct {
	rules         []Rule
	defaultAction RuleAction
}

// NewRuleManager creates a new RuleManager from a semicolon-separated string of rules.
// Each rule is in the format "pattern,ACTION".
func NewRuleManager(ruleEntries []string) *RuleManager {
	rm := &RuleManager{
		rules: make([]Rule, 0),
	}
	// Default defaultAction to ActionProxy as per Match comment,
	// unless overridden by DEFAULT rule.
	rm.defaultAction = ActionProxy

	for _, entry := range ruleEntries {
		parts := strings.SplitN(entry, ",", 2)
		if len(parts) != 2 {
			log.Printf("Router: Invalid rule format: %s. Skipping.", entry)
			continue
		}

		pattern := strings.TrimSpace(parts[0])
		actionStr := strings.ToUpper(strings.TrimSpace(parts[1]))

		var action RuleAction
		switch actionStr {
		case "DIRECT":
			action = ActionDirect
		case "PROXY":
			action = ActionProxy
		default:
			log.Printf("Router: Unknown action '%s' in rule '%s'. Skipping.", actionStr, entry)
			continue
		}

		if strings.ToUpper(pattern) == "DEFAULT" {
			rm.defaultAction = action
			continue
		}

		rm.rules = append(rm.rules, Rule{Pattern: pattern, Action: action})
	}
	return rm
}

// Match matches a host against the configured rules and returns the corresponding action.
// If no rule matches, it defaults to ActionProxy.
func (rm *RuleManager) Match(host string) RuleAction {
	// 1. Check for localhost and loopback IP
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return ActionDirect
	}

	// 2. Check for IP and special ranges
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return ActionDirect
		}
	}

	// 3. Process user-defined rules
	for _, rule := range rm.rules {
		// Basic domain matching: check if host ends with pattern, or is equal
		if strings.HasPrefix(rule.Pattern, ".") { // e.g., .google.com
			trimmedPattern := strings.TrimPrefix(rule.Pattern, ".")
			if host == trimmedPattern || strings.HasSuffix(host, rule.Pattern) {
				return rule.Action
			}
		} else { // e.g., example.com
			if host == rule.Pattern || strings.HasSuffix(host, "."+rule.Pattern) {
				return rule.Action
			}
		}

	}
	// Default to PROXY if no specific rule matches
	return rm.defaultAction
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
	return false
}
