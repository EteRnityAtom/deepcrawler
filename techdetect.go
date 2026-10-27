package main

// URL-pattern-based infrastructure detection. Direct port of
// deep_crawler.py's OAUTH_OIDC_URL_PATTERNS / detect_url_based_tech.
//
// Recon-relevant infrastructure that reveals itself through characteristic
// URL PATHS rather than response headers -- an OAuth2/OIDC identity
// provider in particular is high-value context for an engagement (it
// identifies the real authentication boundary, often a shared SSO tenant
// serving many other apps) but is invisible to header-based tech-detection
// alone. Verified live: discovered on a real production Angular app
// (abgcareers.peoplestrong.com) via its own JS bundle referencing these
// exact Keycloak-style paths, none of which produced any distinguishing
// response header on their own.

import "regexp"

type urlTechPattern struct {
	re    *regexp.Regexp
	label string
}

var oauthOIDCURLPatterns = []urlTechPattern{
	{regexp.MustCompile(`/\.well-known/openid-configuration`), "OAuth2/OIDC Identity Provider (discovery endpoint)"},
	{regexp.MustCompile(`/protocol/openid-connect/(?:auth|token|logout|userinfo|registrations)`), "Keycloak-style OIDC endpoint"},
	{regexp.MustCompile(`/realms/[^/]+/protocol/openid-connect`), "Keycloak realm"},
	{regexp.MustCompile(`/oauth2/(?:authorize|token|revoke)`), "OAuth2 authorization server"},
}

// detectURLBasedTech returns technology signal strings inferred purely
// from the URL's path shape (no response content/headers needed).
func detectURLBasedTech(rawURL string) []string {
	var signals []string
	for _, p := range oauthOIDCURLPatterns {
		if p.re.MatchString(rawURL) {
			signals = append(signals, p.label)
		}
	}
	return signals
}
