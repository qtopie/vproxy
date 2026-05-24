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

// RuleType defines the type of a rule.
type RuleType int

const (
	RuleTypeDomain RuleType = iota
	RuleTypeProcess
)

// Rule represents a single routing rule.
type Rule struct {
	Type    RuleType
	Pattern string
	Action  RuleAction
}

// MatchContext provides context for rule matching.
type MatchContext struct {
	Host    string
	Port    int
	Process string
}

// RuleManager manages a set of routing rules.
type RuleManager struct {
	rules         []Rule
	defaultAction RuleAction
	directDNS     bool
}

// NewRuleManager creates a new RuleManager from a list of rules.
// Rules can be:
// - "DOMAIN,example.com,PROXY"
// - "PROCESS,Telegram,DIRECT"
// - "example.com,PROXY" (defaults to DOMAIN)
// - "DEFAULT,DIRECT"
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
		var pattern, actionStr string

		if len(parts) == 3 {
			typeStr := strings.ToUpper(strings.TrimSpace(parts[0]))
			pattern = strings.TrimSpace(parts[1])
			actionStr = strings.ToUpper(strings.TrimSpace(parts[2]))

			switch typeStr {
			case "DOMAIN":
				ruleType = RuleTypeDomain
			case "PROCESS":
				ruleType = RuleTypeProcess
			default:
				log.Printf("Router: Unknown rule type '%s'. Skipping.", typeStr)
				continue
			}
		} else {
			pattern = strings.TrimSpace(parts[0])
			actionStr = strings.ToUpper(strings.TrimSpace(parts[1]))
		}

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

		rm.rules = append(rm.rules, Rule{Type: ruleType, Pattern: pattern, Action: action})
	}
	return rm
}

// SetDirectDNS sets whether DNS traffic (port 53) should be always DIRECT.
func (rm *RuleManager) SetDirectDNS(direct bool) {
	rm.directDNS = direct
}

// Match matches a host against the configured rules.
func (rm *RuleManager) Match(host string) RuleAction {
	return rm.MatchContext(MatchContext{Host: host})
}

// MatchContext matches a request context against the rules.
func (rm *RuleManager) MatchContext(ctx MatchContext) RuleAction {
	action := rm.doMatchContext(ctx)
	if IsVerbose() {
		Debugf("Router: Match %s (Port: %d, Process: %s) -> %s", ctx.Host, ctx.Port, ctx.Process, action)
	}
	return action
}

func (rm *RuleManager) doMatchContext(ctx MatchContext) RuleAction {
	// 0. Always direct for DNS to avoid UDP relay issues with some upstreams
	if rm.directDNS && ctx.Port == 53 {
		return ActionDirect
	}

	// 1. Check for localhost and loopback IP
	if ctx.Host == "localhost" || ctx.Host == "127.0.0.1" || ctx.Host == "::1" {
		return ActionDirect
	}

	// 2. Check for IP and special ranges
	if ip := net.ParseIP(ctx.Host); ip != nil {
		if isPrivateIP(ip) {
			return ActionDirect
		}
	}

	// 3. Process user-defined rules
	for _, rule := range rm.rules {
		switch rule.Type {
		case RuleTypeProcess:
			if ctx.Process != "" && (ctx.Process == rule.Pattern || strings.Contains(strings.ToLower(ctx.Process), strings.ToLower(rule.Pattern))) {
				return rule.Action
			}
		case RuleTypeDomain:
			host := ctx.Host
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
