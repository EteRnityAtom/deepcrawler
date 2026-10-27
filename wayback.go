package main

// Native passive/historical discovery (replaces gau + waybackurls).
// Direct port of deep_crawler.py's wayback_discovery.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// wafChallengeResourceMarkers identify well-known WAF/anti-bot vendor
// challenge-resource paths -- pure infrastructure noise, never application
// surface. The Wayback Machine's CDX index accumulates one entry per
// distinct historical query string (its own collapse=urlkey parameter
// dedupes only EXACT urlkey matches, and these resources embed a fresh
// cache-busting token on every single page load across years of crawls),
// so a real, actively-challenged site can flood passive discovery with
// hundreds of near-identical entries that differ only in a token/counter --
// confirmed live against abgcareers.peoplestrong.com's Incapsula deployment
// (70+ `_Incapsula_Resource?...&ns=N&cb=M` variants for a single resource).
// Deliberately a narrow, vendor-specific signature list rather than a
// generic "numeric-looking query param" heuristic -- a generic heuristic
// would just as happily collapse genuine pagination (?page=1, ?page=2),
// which are real distinct content and must never be skipped.
var wafChallengeResourceMarkers = []string{
	"_incapsula_resource", // Imperva/Incapsula
	"__cf_chl",            // Cloudflare challenge platform (query-string form)
	"/cdn-cgi/challenge-platform/",
	"/_px/",  // PerimeterX
	"_abck=", // Akamai Bot Manager challenge cookie-sync pings
}

func isLikelyWAFChallengeResource(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	for _, m := range wafChallengeResourceMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// collapseWAFChallengeNoise keeps at most one representative URL per
// query-string-stripped path for anything matching a known WAF-challenge
// signature, passing every other URL through untouched. Applied only to
// passive/historical discovery, where this flood originates -- live
// same-session crawling never encounters more than a handful of these on
// any single page, so it isn't a problem there.
func collapseWAFChallengeNoise(urls map[string]bool) map[string]bool {
	out := make(map[string]bool, len(urls))
	seenPath := make(map[string]bool)
	for u := range urls {
		if !isLikelyWAFChallengeResource(u) {
			out[u] = true
			continue
		}
		pathKey := u
		if parsed, err := url.Parse(u); err == nil {
			pathKey = parsed.Scheme + "://" + parsed.Host + parsed.Path
		}
		if seenPath[pathKey] {
			continue
		}
		seenPath[pathKey] = true
		out[u] = true
	}
	return out
}

// WaybackDiscovery queries the Internet Archive's public CDX API directly
// for historical URLs under the target domain (and subdomains via a
// wildcard match) -- the same public data source gau/waybackurls query,
// without depending on either binary.
func WaybackDiscovery(scope *ScopeManager, timeoutSec int, limit int) map[string]bool {
	found := make(map[string]bool)

	matchType := "exact"
	if scope.includeSubdomains {
		matchType = "domain"
	}

	q := url.Values{}
	q.Set("url", scope.rootDomain)
	q.Set("matchType", matchType)
	q.Set("output", "json")
	q.Set("collapse", "urlkey")
	q.Set("fl", "original")
	q.Set("limit", itoa(limit))

	reqURL := "https://web.archive.org/cdx/search/cdx?" + q.Encode()

	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}
	resp, err := client.Get(reqURL)
	if err != nil {
		logWarn("Wayback CDX passive discovery failed (non-fatal): %v", err)
		return found
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		logWarn("Wayback CDX passive discovery failed (non-fatal): status %d", resp.StatusCode)
		return found
	}

	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		logWarn("Wayback CDX passive discovery failed (non-fatal): %v", err)
		return found
	}

	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue // first row is the field-name header
		}
		u := row[0]
		if scope.InScope(u) {
			found[u] = true
		}
	}
	return collapseWAFChallengeNoise(found)
}
