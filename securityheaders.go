package main

// Security response-header analysis -- standard OWASP-listed recon that
// was previously entirely absent from this tool, despite costing nothing
// extra: every response already carries these headers, they just weren't
// being looked at. Checked once per HOST (not once per URL) since these
// are near-universally set at the web-server/reverse-proxy/CDN layer for
// an entire site, not per-route -- recording it once per host is honest
// signal instead of repeating the identical finding on every single page
// crawled.

import (
	"net/http"
	"strings"
)

// corsProbeOrigin is a syntactically valid but non-existent origin sent as
// the Origin header on every request the crawler makes (see httpretry.go)
// -- zero extra requests needed. If a server reflects THIS back verbatim,
// it demonstrates the server reflects ANY origin, not just ones on some
// real allowlist.
const corsProbeOrigin = "https://deepcrawler-cors-probe.invalid"

// checkCORSReflection inspects one response for the classic CORS
// misconfiguration: reflecting an arbitrary Origin back in
// Access-Control-Allow-Origin while also sending
// Access-Control-Allow-Credentials: true, which lets any attacker-controlled
// site make credentialed cross-origin requests and read the authenticated
// response. A literal "Access-Control-Allow-Origin: *" paired with
// credentials is flagged too, at lower severity -- browsers reject that
// exact combination outright, but it still signals a misconfigured policy
// worth a manual look (some non-browser clients, or a server/proxy stack
// that behaves differently than spec, may still honor it). Returns nil (no
// finding) for the overwhelming majority of responses that don't reflect
// the probe origin at all.
func checkCORSReflection(rawURL string, headers http.Header) map[string]interface{} {
	acao := headers.Get("Access-Control-Allow-Origin")
	acac := strings.ToLower(headers.Get("Access-Control-Allow-Credentials"))

	switch {
	case acao == corsProbeOrigin && acac == "true":
		return map[string]interface{}{
			"type": "cors_origin_reflection_with_credentials", "severity": "high",
			"note":    "Server reflects an arbitrary, attacker-chosen Origin back in Access-Control-Allow-Origin while also sending Access-Control-Allow-Credentials: true -- any site can make credentialed cross-origin requests here and read the authenticated response. Verify manually in Burp (resend with your own Origin).",
			"snippet": rawURL, "source": rawURL,
		}
	case acao == "*" && acac == "true":
		return map[string]interface{}{
			"type": "cors_wildcard_with_credentials", "severity": "medium",
			"note":    "Server sends Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true -- most browsers reject this exact combination, but it indicates a misconfigured CORS policy; verify actual behavior manually.",
			"snippet": rawURL, "source": rawURL,
		}
	}
	return nil
}

type securityHeaderFinding struct {
	Type     string
	Severity string
	Note     string
}

// checkSecurityHeaders inspects one response's headers for common
// missing/weak security controls. isHTTPS gates the HSTS check, which is
// meaningless (and would be a false positive) on a plain-HTTP response.
func checkSecurityHeaders(isHTTPS bool, headers http.Header) []securityHeaderFinding {
	var findings []securityHeaderFinding

	if isHTTPS && headers.Get("Strict-Transport-Security") == "" {
		findings = append(findings, securityHeaderFinding{
			"missing_hsts", "low",
			"No Strict-Transport-Security header on an HTTPS response -- nothing stops a future visit from being silently downgraded to plain HTTP.",
		})
	}

	if headers.Get("X-Content-Type-Options") == "" {
		findings = append(findings, securityHeaderFinding{
			"missing_x_content_type_options", "low",
			"No X-Content-Type-Options: nosniff -- a response can be MIME-sniffed into an executable content type by the browser.",
		})
	}

	csp := headers.Get("Content-Security-Policy")
	xfo := headers.Get("X-Frame-Options")
	hasFrameAncestors := strings.Contains(strings.ToLower(csp), "frame-ancestors")
	if xfo == "" && !hasFrameAncestors {
		findings = append(findings, securityHeaderFinding{
			"missing_clickjacking_protection", "medium",
			"No X-Frame-Options and no CSP frame-ancestors directive -- this page can be framed by any origin (clickjacking).",
		})
	}

	if csp == "" {
		findings = append(findings, securityHeaderFinding{
			"missing_csp", "low",
			"No Content-Security-Policy header -- no defense-in-depth layer against injected script execution if an XSS is otherwise found.",
		})
	} else {
		lowerCSP := strings.ToLower(csp)
		if strings.Contains(lowerCSP, "unsafe-inline") || strings.Contains(lowerCSP, "unsafe-eval") {
			findings = append(findings, securityHeaderFinding{
				"weak_csp", "low",
				"Content-Security-Policy allows 'unsafe-inline' and/or 'unsafe-eval', substantially weakening its value as an XSS mitigation.",
			})
		}
	}

	return findings
}
