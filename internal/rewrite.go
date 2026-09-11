package internal

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

type RewriteType int

const (
	RewriteRegex RewriteType = iota
	RewriteWildcard
	RewriteExact
)

type RewriteAction int

const (
	RewriteActionProxy RewriteAction = iota
	RewriteActionMock
)

func (ra RewriteAction) String() string {
	switch ra {
	case RewriteActionProxy:
		return "PROXY"
	case RewriteActionMock:
		return "MOCK"
	default:
		return "PROXY"
	}
}

type RewriteRule struct {
	Raw    string
	Type   RewriteType
	Host   string
	Regex  *regexp.Regexp
	Target string
	Action RewriteAction
}

type RewriteResult struct {
	Action    RewriteAction
	TargetURL string
	LocalFile string
}

type RewriteEngine struct {
	hostBuckets map[string][]*RewriteRule
	globalRules []*RewriteRule
	allHosts    []string
	mu          sync.RWMutex
}

func NewRewriteEngine(entries []string) (*RewriteEngine, error) {
	engine := &RewriteEngine{
		hostBuckets: make(map[string][]*RewriteRule),
		globalRules: make([]*RewriteRule, 0),
		allHosts:    make([]string, 0),
	}

	hostSet := make(map[string]bool)

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}

		pattern, target := parseRewriteEntry(entry)
		if pattern == "" || target == "" {
			continue
		}

		rule, err := buildRewriteRule(entry, pattern, target)
		if err != nil {
			return nil, fmt.Errorf("invalid rewrite rule %q: %w", entry, err)
		}

		if rule.Host != "" {
			engine.hostBuckets[rule.Host] = append(engine.hostBuckets[rule.Host], rule)
			if !hostSet[rule.Host] {
				hostSet[rule.Host] = true
				engine.allHosts = append(engine.allHosts, rule.Host)
			}
		} else {
			engine.globalRules = append(engine.globalRules, rule)
		}
	}

	return engine, nil
}

func parseRewriteEntry(entry string) (pattern, target string) {
	// First check if it's comma-separated like "MAP,pattern,target"
	if strings.HasPrefix(strings.ToUpper(entry), "MAP,") {
		parts := strings.SplitN(entry, ",", 3)
		if len(parts) >= 3 {
			return strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
		}
	}

	// Otherwise split by whitespace (Whistle style)
	fields := strings.Fields(entry)
	if len(fields) >= 2 {
		return fields[0], fields[1]
	}

	return "", ""
}

func buildRewriteRule(raw, pattern, target string) (*RewriteRule, error) {
	rule := &RewriteRule{
		Raw:    raw,
		Target: target,
		Action: RewriteActionProxy,
	}

	if strings.HasPrefix(target, "file://") {
		rule.Action = RewriteActionMock
	}

	// 1. Is it a Regex rule: /pattern/flags
	if strings.HasPrefix(pattern, "/") && len(pattern) >= 2 {
		lastSlash := strings.LastIndex(pattern, "/")
		if lastSlash > 0 {
			regexBody := pattern[1:lastSlash]
			flags := pattern[lastSlash+1:]

			// Extract Host from regex pattern
			rule.Host = extractHostFromRegexPattern(regexBody)

			if strings.Contains(flags, "i") {
				regexBody = "(?i)" + regexBody
			}
			re, err := regexp.Compile(regexBody)
			if err != nil {
				return nil, err
			}
			rule.Type = RewriteRegex
			rule.Regex = re
			return rule, nil
		}
	}

	// 2. Is it a Wildcard rule: contains '*'
	if strings.Contains(pattern, "*") {
		rule.Type = RewriteWildcard
		rule.Host = extractHostFromWildcard(pattern)

		// Convert wildcard to regex
		regexPattern := wildcardToRegex(pattern)
		re, err := regexp.Compile(regexPattern)
		if err != nil {
			return nil, err
		}
		rule.Regex = re
		return rule, nil
	}

	// 3. Exact URL prefix match
	rule.Type = RewriteExact
	rule.Host = extractHostFromURL(pattern)
	escaped := regexp.QuoteMeta(pattern)
	re, err := regexp.Compile("^" + escaped + "(?:$|\\?|/)")
	if err != nil {
		return nil, err
	}
	rule.Regex = re
	return rule, nil
}

func extractHostFromRegexPattern(regexBody string) string {
	// Clean common escapes to look for host: e.g. "cafe123\.cn\/" or "cafe123.cn\/"
	cleaned := strings.ReplaceAll(regexBody, `\/`, `/`)
	cleaned = strings.ReplaceAll(cleaned, `\.`, `.`)
	cleaned = strings.TrimPrefix(cleaned, "^")
	cleaned = strings.TrimPrefix(cleaned, "https://")
	cleaned = strings.TrimPrefix(cleaned, "http://")
	cleaned = strings.TrimPrefix(cleaned, "//")

	// Cut at first slash or regex delimiter
	idx := strings.IndexAny(cleaned, "/(?[:")
	hostPart := cleaned
	if idx != -1 {
		hostPart = cleaned[:idx]
	}
	hostPart = strings.TrimSpace(hostPart)
	// Verify hostPart looks like a domain or IP (contains '.' or is 'localhost')
	if strings.Contains(hostPart, ".") || hostPart == "localhost" {
		return hostPart
	}
	return ""
}

func extractHostFromWildcard(pattern string) string {
	cleaned := strings.TrimPrefix(pattern, "https://")
	cleaned = strings.TrimPrefix(cleaned, "http://")
	cleaned = strings.TrimPrefix(cleaned, "//")

	idx := strings.Index(cleaned, "/")
	if idx != -1 {
		cleaned = cleaned[:idx]
	}
	// Strip port if present
	if colonIdx := strings.Index(cleaned, ":"); colonIdx != -1 {
		cleaned = cleaned[:colonIdx]
	}
	return strings.TrimSpace(cleaned)
}

func extractHostFromURL(rawURL string) string {
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	if u, err := url.Parse(rawURL); err == nil {
		host := u.Host
		if colonIdx := strings.Index(host, ":"); colonIdx != -1 {
			host = host[:colonIdx]
		}
		return host
	}
	return ""
}

func wildcardToRegex(pattern string) string {
	// Split by '*'
	parts := strings.Split(pattern, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	// Join with (.*)
	inner := strings.Join(parts, "(.*)")
	// Support matching both http and https if not specified
	if !strings.HasPrefix(pattern, "http://") && !strings.HasPrefix(pattern, "https://") && !strings.HasPrefix(pattern, "//") {
		return `^(?:https?:)?(?://)?` + inner + `$`
	}
	return `^` + inner + `$`
}

func (re *RewriteEngine) GetInterceptHosts() []string {
	re.mu.RLock()
	defer re.mu.RUnlock()
	res := make([]string, len(re.allHosts))
	copy(res, re.allHosts)
	return res
}

func (re *RewriteEngine) IsInterceptHost(host string) bool {
	re.mu.RLock()
	defer re.mu.RUnlock()
	if _, ok := re.hostBuckets[host]; ok {
		return true
	}
	return false
}

func (re *RewriteEngine) Match(reqURL, host string) (*RewriteResult, bool) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	if host == "" {
		if u, err := url.Parse(reqURL); err == nil {
			host = u.Hostname()
		}
	}

	// 1. Host-Bucket fast-path: check specific host bucket
	if rules, ok := re.hostBuckets[host]; ok {
		for _, rule := range rules {
			if res, ok := evaluateRule(rule, reqURL); ok {
				return res, true
			}
		}
	}

	// 2. Fallback to global rules
	for _, rule := range re.globalRules {
		if res, ok := evaluateRule(rule, reqURL); ok {
			return res, true
		}
	}

	return nil, false
}

func evaluateRule(rule *RewriteRule, reqURL string) (*RewriteResult, bool) {
	if !rule.Regex.MatchString(reqURL) {
		return nil, false
	}

	res := &RewriteResult{
		Action: rule.Action,
	}

	if rule.Action == RewriteActionMock {
		res.LocalFile = strings.TrimPrefix(rule.Target, "file://")
		return res, true
	}

	// Proxy Rewrite: compute target URL
	if strings.Contains(rule.Target, "$") {
		submatches := rule.Regex.FindStringSubmatchIndex(reqURL)
		if len(submatches) > 0 {
			res.TargetURL = string(rule.Regex.ExpandString(nil, rule.Target, reqURL, submatches))
		} else {
			res.TargetURL = rule.Regex.ReplaceAllString(reqURL, rule.Target)
		}
	} else {
		// Auto Path Append
		u, err := url.Parse(reqURL)
		pathAndQuery := ""
		if err == nil {
			pathAndQuery = u.EscapedPath()
			if u.RawQuery != "" {
				pathAndQuery += "?" + u.RawQuery
			}
		}

		targetBase := rule.Target
		if strings.HasSuffix(targetBase, "/") && strings.HasPrefix(pathAndQuery, "/") {
			res.TargetURL = strings.TrimSuffix(targetBase, "/") + pathAndQuery
		} else if !strings.HasSuffix(targetBase, "/") && !strings.HasPrefix(pathAndQuery, "/") {
			res.TargetURL = targetBase + "/" + pathAndQuery
		} else {
			res.TargetURL = targetBase + pathAndQuery
		}
	}

	return res, true
}
