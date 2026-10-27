package main

// Scope management -- direct port of deep_crawler.py's ScopeManager.
//
// Central scope authority. Every URL discovered anywhere in the crawler
// (HTML links, JS-extracted paths, passive/historical sources) is
// re-checked here -- this is the single chokepoint that guarantees the
// crawler never fetches or records anything outside the target domain and
// its subdomains.

import (
	"net/url"
	"regexp"
	"strings"
)

type ScopeManager struct {
	rootDomain        string
	includeSubdomains bool
	extraDomains      map[string]bool
	excludeRe         []*regexp.Regexp
}

func NewScopeManager(targetURL string, includeSubdomains bool, extraDomains []string, excludePatterns []string) (*ScopeManager, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	extra := make(map[string]bool)
	for _, d := range extraDomains {
		extra[strings.ToLower(d)] = true
	}

	var excludeRe []*regexp.Regexp
	for _, p := range excludePatterns {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			continue // same defensive skip-on-bad-pattern posture as the Python version
		}
		excludeRe = append(excludeRe, re)
	}

	return &ScopeManager{
		rootDomain:        strings.ToLower(parsed.Host),
		includeSubdomains: includeSubdomains,
		extraDomains:      extra,
		excludeRe:         excludeRe,
	}, nil
}

// InScope mirrors ScopeManager.in_scope exactly: exact domain match, or
// (if subdomains are included) a `.`-anchored subdomain match, rejecting
// non-network pseudo-schemes (javascript:, mailto:, tel:, data:, ...)
// outright since those are never crawl targets. ws/wss are real network
// schemes over the same domain (WebSocket endpoints discovered in bundled
// JS) and are allowed through the same domain-matching logic below, even
// though they're recorded as findings rather than queued for an HTTP fetch.
func (s *ScopeManager) InScope(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	domain := strings.ToLower(parsed.Host)
	if domain == "" {
		return false
	}
	switch parsed.Scheme {
	case "http", "https", "ws", "wss", "":
	default:
		return false
	}

	allowed := domain == s.rootDomain || s.extraDomains[domain]
	if s.includeSubdomains && !allowed {
		if strings.HasSuffix(domain, "."+s.rootDomain) {
			allowed = true
		}
		if !allowed {
			for d := range s.extraDomains {
				if strings.HasSuffix(domain, "."+d) {
					allowed = true
					break
				}
			}
		}
	}

	if !allowed {
		return false
	}

	for _, pattern := range s.excludeRe {
		if pattern.MatchString(rawURL) {
			return false
		}
	}

	return true
}
