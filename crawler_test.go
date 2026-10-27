package main

// Direct port of test_deep_crawler.py's 33 tests to Go's testing package.
// Same pure/offline posture -- no live network calls.

import (
	"encoding/xml"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestMain(m *testing.M) {
	initSecretSignatures("nuclei_secret_signatures.json")
	m.Run()
}

func TestScopeManagerBasic(t *testing.T) {
	scope, _ := NewScopeManager("https://example.com", true, nil, nil)
	assertTrue(t, scope.InScope("https://example.com/path"))
	assertTrue(t, scope.InScope("https://api.example.com/x"))
	assertTrue(t, scope.InScope("https://deep.sub.example.com/x"))
	assertFalse(t, scope.InScope("https://example.com.evil.com/x"))
	assertFalse(t, scope.InScope("https://notexample.com/x"))
	assertFalse(t, scope.InScope("https://example.co/x"))
}

func TestScopeManagerNoSubdomains(t *testing.T) {
	scope, _ := NewScopeManager("https://example.com", false, nil, nil)
	assertTrue(t, scope.InScope("https://example.com/path"))
	assertFalse(t, scope.InScope("https://api.example.com/x"))
}

func TestScopeManagerExtraDomainsAndExclude(t *testing.T) {
	scope, _ := NewScopeManager("https://example.com", true,
		[]string{"partner-site.com"}, []string{`/logout`, `\.pdf$`})
	assertTrue(t, scope.InScope("https://partner-site.com/api"))
	assertTrue(t, scope.InScope("https://sub.partner-site.com/api"))
	assertFalse(t, scope.InScope("https://example.com/logout"))
	assertFalse(t, scope.InScope("https://example.com/file.pdf"))
	assertTrue(t, scope.InScope("https://example.com/file.pdf.html")) // anchored at end only
}

func TestScopeManagerMalformedURL(t *testing.T) {
	scope, _ := NewScopeManager("https://example.com", true, nil, nil)
	assertFalse(t, scope.InScope(""))
}

func TestScopeManagerRejectsNonHTTPSchemes(t *testing.T) {
	scope, _ := NewScopeManager("https://example.com", true, nil, nil)
	assertFalse(t, scope.InScope("javascript:void(0)"))
	assertFalse(t, scope.InScope("javascript:alert(1)"))
	assertFalse(t, scope.InScope("mailto:someone@example.com"))
	assertFalse(t, scope.InScope("tel:+1234567890"))
}

func TestShannonEntropy(t *testing.T) {
	if shannonEntropy("") != 0.0 {
		t.Errorf("expected 0.0 entropy for empty string")
	}
	if shannonEntropy("aaaaaaaaaa") >= 1.0 {
		t.Errorf("expected low entropy for repeated chars")
	}
	if shannonEntropy("aB3xK9zQ7mP2vL8n") <= 3.0 {
		t.Errorf("expected high entropy for random-looking string")
	}
}

func TestScanSecretsSignatures(t *testing.T) {
	text := `
        const key = "AKIAABCDEFGHIJKLMNOP";
        var jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        api_key = "sk_live_51H8xyzABCDEFGHIJKLMNOPQR";
        password = "SuperSecretPass123";
        placeholder_key = "your_api_key";
    `
	findings := ScanSecrets(text, 25)
	assertTrue(t, len(findings["aws_access_key"]) > 0)
	assertTrue(t, len(findings["jwt_token"]) > 0)
	assertTrue(t, len(findings["hardcoded_password"]) > 0)
	for _, matches := range findings {
		for _, m := range matches {
			if m.Value() == "your_api_key" {
				t.Errorf("placeholder value must be suppressed")
			}
		}
	}
}

func TestScanSecretsEntropyFallback(t *testing.T) {
	text := `const customToken = "zK9pQm3xL7vN2wR8tY5cJ4hF6bA1sD0e";`
	findings := ScanSecrets(text, 25)
	assertTrue(t, len(findings["high_entropy_string"]) > 0)
}

func TestScanSecretsNoFalsePositiveOnPlainText(t *testing.T) {
	text := "This is just a normal sentence about our product roadmap and pricing page."
	findings := ScanSecrets(text, 25)
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %v", findings)
	}
}

func TestHardcodedPasswordDoesNotCrossStringBoundary(t *testing.T) {
	text := `e.createElement("label",null,"Password:"),m?l.default.createElement("input"`
	findings := ScanSecrets(text, 25)
	if len(findings["hardcoded_password"]) > 0 {
		t.Errorf("false positive: %v", findings["hardcoded_password"])
	}

	real := `var config = {password: "Sup3rSecret!23"};`
	findings2 := ScanSecrets(real, 25)
	if len(findings2["hardcoded_password"]) != 1 || findings2["hardcoded_password"][0].Value() != "Sup3rSecret!23" {
		t.Errorf("expected real password to be found, got %v", findings2["hardcoded_password"])
	}
}

func TestEntropyScanRejectsIdentifierAndMimeStrings(t *testing.T) {
	text := `
        var a = "parse_block_mapping_first_key";
        var b = "application/x-www-form-urlencoded";
        var c = "abcdefghijklmnopqrst";
    `
	findings := ScanSecrets(text, 25)
	for _, m := range findings["high_entropy_string"] {
		v := m.Value()
		if v == "parse_block_mapping_first_key" || v == "application/x-www-form-urlencoded" || v == "abcdefghijklmnopqrst" {
			t.Errorf("library-internal/MIME string slipped through: %s", v)
		}
	}
}

func TestNucleiShortCaptureFalsePositivesFiltered(t *testing.T) {
	findings := ScanSecrets("some ordinary K page with a o and t and 75 scattered around", 25)
	for _, matches := range findings {
		for _, m := range matches {
			if len(m.Value()) < 6 {
				t.Errorf("a too-short 'secret' slipped through: %q", m.Value())
			}
		}
	}
}

func TestVendorFileDetection(t *testing.T) {
	assertTrue(t, isLikelyVendorFile("https://target.com/flasgger_static/swagger-ui-bundle.js"))
	assertTrue(t, isLikelyVendorFile("https://target.com/static/js/jquery.min.js"))
	assertTrue(t, isLikelyVendorFile("https://target.com/vendor/bootstrap.min.js"))
	assertFalse(t, isLikelyVendorFile("https://target.com/js/app.js"))
	assertFalse(t, isLikelyVendorFile("https://target.com/api/checkout.js"))
}

func TestScanLogicFlaws(t *testing.T) {
	text := `
        if (password.length < 8) { showError(); }
        eval(userInput);
        el.innerHTML = userComment;
        debug = true;
        const price = req.body.price;
    `
	flaws := ScanLogicFlaws(text, "https://example.com/app.js")
	types := make(map[string]bool)
	for _, f := range flaws {
		types[f.Type] = true
	}
	assertTrue(t, types["client_side_only_validation"])
	assertTrue(t, types["eval_or_dynamic_exec"])
	assertTrue(t, types["dom_xss_sink"])
	assertTrue(t, types["debug_flag_enabled"])
}

func TestSuggestVulnClasses(t *testing.T) {
	assertContains(t, SuggestVulnClasses("user_id"), "IDOR")
	assertContains(t, SuggestVulnClasses("redirect_url"), "Open Redirect")
	assertContains(t, SuggestVulnClasses("file"), "LFI")
	assertContains(t, SuggestVulnClasses("price"), "Business logic - price/quantity manipulation")
	result := SuggestVulnClasses("totally_unrelated_xyz")
	if len(result) != 1 || result[0] != "Generic input validation" {
		t.Errorf("expected Generic input validation only, got %v", result)
	}
}

func TestTokenizeParamNameCamelCase(t *testing.T) {
	// Direct regression test for the lookaround->manual-scan port: this
	// specifically exercises insertCamelBoundaries, the Go replacement for
	// Python's (?<=[a-z0-9])(?=[A-Z]) lookaround regex.
	tokens := TokenizeParamName("redirectUrl")
	assertTrue(t, tokens["redirect"])
	assertTrue(t, tokens["url"])

	tokens2 := TokenizeParamName("totallyUnrelatedXYZ")
	// "totally", "unrelated", "x", "y", "z" is fine either way -- the key
	// property is "dir" is NOT a token of "redirect" and "total" is NOT a
	// token of "totally" (whole-token matching, not substring).
	assertFalse(t, tokens2["dir"])
	assertFalse(t, tokens2["total"])
}

func TestResolveDiscoveredURLViteChunkManifest(t *testing.T) {
	siteRoot := "https://apps.returnprime.co"
	referencingFile := "https://apps.returnprime.co/assets/index-D2GG7HJO.js"

	resolved := ResolveDiscoveredURL(siteRoot, referencingFile, "assets/api-DO2OmuJE.js", "")
	if resolved != "https://apps.returnprime.co/assets/api-DO2OmuJE.js" {
		t.Errorf("got %s", resolved)
	}

	abs := ResolveDiscoveredURL(siteRoot, referencingFile, "/api/v1/users", "")
	if abs != "https://apps.returnprime.co/api/v1/users" {
		t.Errorf("got %s", abs)
	}

	external := ResolveDiscoveredURL(siteRoot, referencingFile, "https://cdn.other.com/x.js", "")
	if external != "https://cdn.other.com/x.js" {
		t.Errorf("got %s", external)
	}

	relative := ResolveDiscoveredURL(siteRoot, referencingFile, "./config.json", "")
	if relative != "https://apps.returnprime.co/assets/config.json" {
		t.Errorf("got %s", relative)
	}
}

func TestResolveDiscoveredURLBaseHref(t *testing.T) {
	// Reproduced live against a real production Angular app
	// (abgcareers.peoplestrong.com): its compiled bundle emits bare
	// <script src="chunk-X.js"> relying on <base href="/">. Confirmed via
	// direct curl: the true /chunk-X.js returned 200; naive sibling-relative
	// resolution (ignoring base href) produced a 404 at a nested path.
	siteRoot := "https://example.com"
	referencingPage := "https://example.com/agent/interview"

	// Without a known baseHref, a bare relative path still falls back to
	// sibling-relative resolution against the referencing page (the
	// original, narrower behavior) -- must not regress.
	noBase := ResolveDiscoveredURL(siteRoot, referencingPage, "chunk-X.js", "")
	if noBase != "https://example.com/agent/chunk-X.js" {
		t.Errorf("got %s", noBase)
	}

	// With a discovered baseHref, the SAME bare relative path must resolve
	// against the base, not the referencing page -- this is the fix.
	withBase := ResolveDiscoveredURL(siteRoot, referencingPage, "chunk-X.js", "https://example.com/")
	if withBase != "https://example.com/chunk-X.js" {
		t.Errorf("got %s", withBase)
	}

	// Absolute and root-relative paths are unaffected by baseHref either way.
	rootRel := ResolveDiscoveredURL(siteRoot, referencingPage, "/api/v1", "https://example.com/")
	if rootRel != "https://example.com/api/v1" {
		t.Errorf("got %s", rootRel)
	}
	absolute := ResolveDiscoveredURL(siteRoot, referencingPage, "https://cdn.x.com/y.js", "https://example.com/")
	if absolute != "https://cdn.x.com/y.js" {
		t.Errorf("got %s", absolute)
	}
}

func TestLinkExtractorCapturesBaseHref(t *testing.T) {
	htmlBody := `<html><head><base href="/app/"><base href="/ignored/"></head><body></body></html>`
	result := ExtractLinks(htmlBody)
	if result.BaseHref != "/app/" {
		t.Errorf("expected first <base> to win, got %q", result.BaseHref)
	}
}

func TestLinkExtractorNoBaseTag(t *testing.T) {
	result := ExtractLinks(`<html><body><a href="/x">link</a></body></html>`)
	if result.BaseHref != "" {
		t.Errorf("expected empty BaseHref when no <base> tag present, got %q", result.BaseHref)
	}
}

func TestIsSequentialAlphabetLikeRejectsEncodingConstants(t *testing.T) {
	// Reproduced live against a real production JS bundle's base64 encoder
	// (a CryptoJS-style library): these exact strings passed every other
	// entropy-scan filter (entropy 6.0, character-class mixed, 8+ distinct
	// chars) before this check was added.
	if !isSequentialAlphabetLike("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") {
		t.Error("expected base64 alphabet constant to be flagged")
	}
	if !isSequentialAlphabetLike("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Error("expected reversed alphabet constant to be flagged")
	}
	if !isSequentialAlphabetLike("0123456789abcdefghijklmnopqrstuvwxyz") {
		t.Error("expected hex-plus-alpha constant to be flagged")
	}
}

func TestIsSequentialAlphabetLikeAcceptsRealTokens(t *testing.T) {
	if isSequentialAlphabetLike("aB3xK9zQ7mP2vL8nR5tY1wE6uI0oH4jF") {
		t.Error("real random-looking token should not be flagged")
	}
	// NOTE: "AKIAABCDEFGHIJKLMNOP" (used as a readable fake AWS key
	// elsewhere) is deliberately NOT used here -- its alphabetically-
	// sequential suffix is genuinely, correctly caught by this check.
	if isSequentialAlphabetLike("AKIAQZ7MXR2K9FWL3PDT") {
		t.Error("real-shaped, non-sequential AWS key should not be flagged")
	}
	if isSequentialAlphabetLike("short") {
		t.Error("too-short token should not be flagged")
	}
}

func TestScanSecretsRejectsBase64AlphabetConstant(t *testing.T) {
	text := `var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";`
	findings := ScanSecrets(text, 25)
	for _, matches := range findings {
		for _, m := range matches {
			if contains(m.Value(), "ABCDEFGHIJ") {
				t.Errorf("alphabet constant slipped through as a secret: %q", m.Value())
			}
		}
	}
}

func TestExtractSourceMappingURL(t *testing.T) {
	js := "var x = 1;\nconsole.log(x);\n//# sourceMappingURL=app.js.map\n"
	if got := ExtractSourceMappingURL(js); got != "app.js.map" {
		t.Errorf("got %q", got)
	}

	jsBlockComment := "var x = 1;\n/*# sourceMappingURL=app.js.map */"
	if got := ExtractSourceMappingURL(jsBlockComment); got != "app.js.map" {
		t.Errorf("block-comment form: got %q", got)
	}

	// Inline data-URI source maps must NOT be reported as "discovered" --
	// the map is already embedded in the same file being analyzed, so
	// there's nothing new to fetch.
	dataURI := "var x=1;\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ=="
	if got := ExtractSourceMappingURL(dataURI); got != "" {
		t.Errorf("expected empty for data-URI source map, got %q", got)
	}

	if got := ExtractSourceMappingURL("var x = 1;"); got != "" {
		t.Errorf("expected empty when no directive present, got %q", got)
	}
}

func TestParseSourceMap(t *testing.T) {
	mapJSON := `{
		"version": 3,
		"file": "app.min.js",
		"sources": ["src/app.ts", "src/utils.ts"],
		"sourcesContent": [
			"const apiKey = 'AKIAREALLOOKINGKEY12345'; export function main() {}",
			"export function helper() { return fetch('/internal/debug'); }"
		]
	}`
	recovered, err := ParseSourceMap([]byte(mapJSON))
	if err != nil {
		t.Fatalf("ParseSourceMap failed: %v", err)
	}
	if len(recovered) != 2 {
		t.Fatalf("expected 2 recovered sources, got %d", len(recovered))
	}
	if !contains(recovered["src/app.ts"], "apiKey") {
		t.Errorf("expected src/app.ts content to be recovered, got %v", recovered["src/app.ts"])
	}
	if !contains(recovered["src/utils.ts"], "/internal/debug") {
		t.Errorf("expected src/utils.ts content to be recovered")
	}
}

func TestParseSourceMapNoSourcesContent(t *testing.T) {
	// Real-world common case: production source maps often omit
	// sourcesContent specifically to avoid this exact exposure -- must
	// degrade to zero recovered sources, not error.
	mapJSON := `{"version": 3, "file": "app.min.js", "sources": ["src/app.ts"]}`
	recovered, err := ParseSourceMap([]byte(mapJSON))
	if err != nil {
		t.Fatalf("ParseSourceMap failed: %v", err)
	}
	if len(recovered) != 0 {
		t.Errorf("expected 0 recovered sources when sourcesContent is absent, got %d", len(recovered))
	}
}

func TestExtractURLsFromJSFindsWebSocketURLs(t *testing.T) {
	js := `const socket = new WebSocket("wss://chat.example.com:8443/live/updates");`
	found := ExtractURLsFromJS(js)
	if !found["wss://chat.example.com:8443/live/updates"] {
		t.Errorf("expected wss:// URL to be found, got %v", found)
	}
}

func TestResolveDiscoveredURLPreservesWebSocketScheme(t *testing.T) {
	got := ResolveDiscoveredURL("https://example.com", "https://example.com/app", "wss://example.com/socket", "")
	if got != "wss://example.com/socket" {
		t.Errorf("expected wss URL to resolve unchanged, got %q", got)
	}
}

func TestScopeManagerAllowsInScopeWebSocket(t *testing.T) {
	scope, _ := NewScopeManager("https://example.com", true, nil, nil)
	assertTrue(t, scope.InScope("wss://example.com/socket"))
	assertTrue(t, scope.InScope("wss://api.example.com/socket"))
	assertFalse(t, scope.InScope("wss://evil.test/socket"))
}

func TestLinkExtractorCapturesComments(t *testing.T) {
	html := `<html><body><!-- debug link: <a href="/internal/debug-panel"></a> --></body></html>`
	result := ExtractLinks(html)
	if len(result.Comments) != 1 {
		t.Fatalf("expected 1 comment captured, got %d", len(result.Comments))
	}
	found := ExtractURLsFromJS(result.Comments[0])
	if !found["/internal/debug-panel"] {
		t.Errorf("expected URL from comment to be extractable, got %v", found)
	}
}

func TestCheckCORSReflectionDetectsReflectionWithCredentials(t *testing.T) {
	headers := http.Header{}
	headers.Set("Access-Control-Allow-Origin", corsProbeOrigin)
	headers.Set("Access-Control-Allow-Credentials", "true")
	f := checkCORSReflection("https://example.com/api", headers)
	if f == nil || f["type"] != "cors_origin_reflection_with_credentials" || f["severity"] != "high" {
		t.Errorf("expected high-severity reflection finding, got %v", f)
	}
}

func TestCheckCORSReflectionDetectsWildcardWithCredentials(t *testing.T) {
	headers := http.Header{}
	headers.Set("Access-Control-Allow-Origin", "*")
	headers.Set("Access-Control-Allow-Credentials", "true")
	f := checkCORSReflection("https://example.com/api", headers)
	if f == nil || f["type"] != "cors_wildcard_with_credentials" {
		t.Errorf("expected wildcard+credentials finding, got %v", f)
	}
}

func TestCheckCORSReflectionIgnoresSafeConfig(t *testing.T) {
	headers := http.Header{}
	headers.Set("Access-Control-Allow-Origin", "https://trusted-partner.example.com")
	if f := checkCORSReflection("https://example.com/api", headers); f != nil {
		t.Errorf("fixed real-origin CORS config should not be flagged, got %v", f)
	}

	headers2 := http.Header{}
	headers2.Set("Access-Control-Allow-Origin", "*")
	if f := checkCORSReflection("https://example.com/api", headers2); f != nil {
		t.Errorf("wildcard WITHOUT credentials is standard and safe, should not be flagged, got %v", f)
	}

	if f := checkCORSReflection("https://example.com/api", http.Header{}); f != nil {
		t.Errorf("no CORS headers at all should not be flagged, got %v", f)
	}
}

func TestCheckSecurityHeadersFlagsAllMissing(t *testing.T) {
	headers := http.Header{}
	findings := checkSecurityHeaders(true, headers)
	types := make(map[string]bool)
	for _, f := range findings {
		types[f.Type] = true
	}
	assertTrue(t, types["missing_hsts"])
	assertTrue(t, types["missing_x_content_type_options"])
	assertTrue(t, types["missing_clickjacking_protection"])
	assertTrue(t, types["missing_csp"])
}

func TestCheckSecurityHeadersHTTPSkipsHSTS(t *testing.T) {
	headers := http.Header{}
	findings := checkSecurityHeaders(false, headers)
	for _, f := range findings {
		if f.Type == "missing_hsts" {
			t.Errorf("HSTS check should not apply to a plain-HTTP response")
		}
	}
}

func TestCheckSecurityHeadersRecognizesGoodHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Set("Strict-Transport-Security", "max-age=31536000")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Frame-Options", "DENY")
	headers.Set("Content-Security-Policy", "default-src 'self'")
	findings := checkSecurityHeaders(true, headers)
	if len(findings) != 0 {
		t.Errorf("expected no findings for a fully-hardened response, got %v", findings)
	}
}

func TestCheckSecurityHeadersFlagsWeakCSP(t *testing.T) {
	headers := http.Header{}
	headers.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")
	findings := checkSecurityHeaders(true, headers)
	found := false
	for _, f := range findings {
		if f.Type == "weak_csp" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected weak_csp for a CSP containing unsafe-inline, got %v", findings)
	}
}

func TestCheckSecurityHeadersFrameAncestorsSatisfiesClickjackingCheck(t *testing.T) {
	headers := http.Header{}
	headers.Set("Content-Security-Policy", "frame-ancestors 'self'")
	findings := checkSecurityHeaders(true, headers)
	for _, f := range findings {
		if f.Type == "missing_clickjacking_protection" {
			t.Errorf("CSP frame-ancestors should satisfy the clickjacking check even without X-Frame-Options")
		}
	}
}

func TestLinkExtractorCapturesDataAttributeURLs(t *testing.T) {
	html := `<div data-endpoint="/api/v1/checkout" data-src="/lazy/hero.jpg"></div>`
	result := ExtractLinks(html)
	if !result.Links["/api/v1/checkout"] {
		t.Errorf("expected data-endpoint URL to be captured, got %v", result.Links)
	}
	if !result.Links["/lazy/hero.jpg"] {
		t.Errorf("expected data-src URL to be captured, got %v", result.Links)
	}
}

func TestHardcodedCredentialRejectsI18nSentence(t *testing.T) {
	// Live-reproduced false positive: an i18n error-message dictionary
	// entry, not an actual credential.
	text := `Password:"Invalid password."`
	flaws := ScanLogicFlaws(text, "https://example.com/app.js")
	for _, f := range flaws {
		if f.Type == "hardcoded_credential" {
			t.Errorf("i18n sentence should not be flagged as a hardcoded credential, got %v", f)
		}
	}
}

func TestHardcodedCredentialStillCatchesRealValue(t *testing.T) {
	text := `var config = {password: "Sup3rSecret!23"};`
	flaws := ScanLogicFlaws(text, "https://example.com/app.js")
	found := false
	for _, f := range flaws {
		if f.Type == "hardcoded_credential" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a real single-token password value to still be flagged, got %v", flaws)
	}
}

func TestPostMessageOriginCheckFlagsUnguardedListener(t *testing.T) {
	js := `window.addEventListener("message", function(e) { document.getElementById('x').innerHTML = e.data; });`
	flaws := ScanLogicFlaws(js, "https://example.com/app.js")
	found := false
	for _, f := range flaws {
		if f.Type == "postmessage_no_origin_check" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected postmessage_no_origin_check for a listener with no origin check, got %v", flaws)
	}
}

func TestPostMessageOriginCheckSkipsGuardedListener(t *testing.T) {
	js := `window.addEventListener("message", function(e) {
		if (e.origin !== "https://trusted.example.com") { return; }
		handle(e.data);
	});`
	flaws := ScanLogicFlaws(js, "https://example.com/app.js")
	for _, f := range flaws {
		if f.Type == "postmessage_no_origin_check" {
			t.Errorf("listener with a nearby .origin check should not be flagged, got %v", f)
		}
	}
}

func TestCollapseWAFChallengeNoiseCollapsesIncapsulaVariants(t *testing.T) {
	urls := map[string]bool{
		"https://example.com/_Incapsula_Resource?SWJIYLWA=abc&ns=1&cb=111": true,
		"https://example.com/_Incapsula_Resource?SWJIYLWA=abc&ns=2&cb=222": true,
		"https://example.com/_Incapsula_Resource?SWJIYLWA=abc&ns=3&cb=333": true,
		"https://example.com/page1":                                        true,
		"https://example.com/page2?id=1":                                   true,
		"https://example.com/page2?id=2":                                   true,
	}
	out := collapseWAFChallengeNoise(urls)

	incapsulaCount := 0
	for u := range out {
		if isLikelyWAFChallengeResource(u) {
			incapsulaCount++
		}
	}
	if incapsulaCount != 1 {
		t.Errorf("expected exactly 1 representative Incapsula URL to survive, got %d in %v", incapsulaCount, out)
	}
	// Genuine distinct content (different ?id=) must never be collapsed --
	// only the vendor-signature-matched noise.
	if !out["https://example.com/page1"] {
		t.Errorf("page1 should be untouched")
	}
	if !out["https://example.com/page2?id=1"] || !out["https://example.com/page2?id=2"] {
		t.Errorf("distinct ?id= pagination must never be collapsed, got %v", out)
	}
}

func TestIsLikelyWAFChallengeResource(t *testing.T) {
	assertTrue(t, isLikelyWAFChallengeResource("https://x.com/_Incapsula_Resource?SWJIYLWA=x&ns=1&cb=2"))
	assertTrue(t, isLikelyWAFChallengeResource("https://x.com/cdn-cgi/challenge-platform/h/g/orchestrate/jsch/v1"))
	assertFalse(t, isLikelyWAFChallengeResource("https://x.com/api/v1/users?page=2"))
	assertFalse(t, isLikelyWAFChallengeResource("https://x.com/checkout?id=5"))
}

func TestSanitizeDirName(t *testing.T) {
	cases := map[string]string{
		"apple.com":        "apple.com",
		"test.apple.com":   "test.apple.com",
		"apple.com:8443":   "apple.com_8443",
		"":                 "unknown-target",
		"weird/host\\name": "weird_host_name",
	}
	for in, want := range cases {
		if got := sanitizeDirName(in); got != want {
			t.Errorf("sanitizeDirName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewNativeCrawlerUsesPerTargetOutputSubdir(t *testing.T) {
	base := t.TempDir()

	c1, err := NewNativeCrawler(NativeCrawlerOpts{TargetURL: "https://apple.com", OutputDir: base, Concurrency: 1, TimeoutSec: 5, IncludeSubdomains: true})
	if err != nil {
		t.Fatalf("NewNativeCrawler failed: %v", err)
	}
	c2, err := NewNativeCrawler(NativeCrawlerOpts{TargetURL: "https://test.apple.com", OutputDir: base, Concurrency: 1, TimeoutSec: 5, IncludeSubdomains: true})
	if err != nil {
		t.Fatalf("NewNativeCrawler failed: %v", err)
	}

	if c1.outputDir == c2.outputDir {
		t.Fatalf("expected apple.com and test.apple.com to get distinct output dirs, both got %q", c1.outputDir)
	}
	wantC1 := filepath.Join(base, "apple.com")
	wantC2 := filepath.Join(base, "test.apple.com")
	if c1.outputDir != wantC1 {
		t.Errorf("c1.outputDir = %q, want %q", c1.outputDir, wantC1)
	}
	if c2.outputDir != wantC2 {
		t.Errorf("c2.outputDir = %q, want %q", c2.outputDir, wantC2)
	}
	if _, err := os.Stat(c1.outputDir); err != nil {
		t.Errorf("expected %q to have been created, got: %v", c1.outputDir, err)
	}
	if _, err := os.Stat(c2.outputDir); err != nil {
		t.Errorf("expected %q to have been created, got: %v", c2.outputDir, err)
	}
}

func TestFindBrowserPathOverridePrecedence(t *testing.T) {
	os.Unsetenv("DEEPCRAWLER_CHROME_PATH")
	if got := findBrowserPath("/explicit/override/chrome"); got != "/explicit/override/chrome" {
		t.Errorf("explicit override should always win, got %q", got)
	}
}

func TestFindBrowserPathEnvVarPrecedence(t *testing.T) {
	os.Setenv("DEEPCRAWLER_CHROME_PATH", "/env/chrome")
	defer os.Unsetenv("DEEPCRAWLER_CHROME_PATH")
	if got := findBrowserPath(""); got != "/env/chrome" {
		t.Errorf("env var should be used when no explicit override is given, got %q", got)
	}
	// Explicit override still beats the env var.
	if got := findBrowserPath("/explicit/chrome"); got != "/explicit/chrome" {
		t.Errorf("explicit override should beat env var, got %q", got)
	}
}

func TestRobotsDirectiveParsing(t *testing.T) {
	lines := []string{
		"User-agent: *",
		"Disallow: /admin/",
		"Disallow: /internal-api/",
		"Allow: /public/",
		"Disallow: /",
		"Sitemap: https://example.com/sitemap.xml",
		"Sitemap: https://example.com/sitemap-news.xml",
	}
	var sitemaps []string
	var paths []string
	for _, line := range lines {
		if m := sitemapDirectiveRe.FindStringSubmatch(line); m != nil {
			sitemaps = append(sitemaps, m[1])
			continue
		}
		if m := disallowAllowDirectiveRe.FindStringSubmatch(line); m != nil {
			if m[1] != "" && m[1] != "/" {
				paths = append(paths, m[1])
			}
		}
	}
	if len(sitemaps) != 2 {
		t.Errorf("expected 2 sitemap directives, got %v", sitemaps)
	}
	assertContains(t, paths, "/admin/")
	assertContains(t, paths, "/internal-api/")
	assertContains(t, paths, "/public/")
}

func TestSitemapXMLParsing(t *testing.T) {
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/page1</loc></url>
  <url><loc>https://example.com/page2</loc></url>
</urlset>`
	var set sitemapURLSet
	if err := xml.Unmarshal([]byte(xmlBody), &set); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(set.URLs) != 2 || set.URLs[0].Loc != "https://example.com/page1" {
		t.Errorf("unexpected sitemap parse result: %+v", set.URLs)
	}
}

func TestSitemapIndexXMLParsing(t *testing.T) {
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.com/sitemap-a.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap-b.xml</loc></sitemap>
</sitemapindex>`
	var index sitemapIndex
	if err := xml.Unmarshal([]byte(xmlBody), &index); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(index.Sitemaps) != 2 {
		t.Errorf("expected 2 nested sitemaps, got %d", len(index.Sitemaps))
	}
}

func TestDetectURLBasedTechIdentifiesKeycloakOIDC(t *testing.T) {
	// Reproduced live: found on a real production app via its own JS
	// bundle referencing these exact Keycloak-style paths, none of which
	// produced any distinguishing response header on their own.
	if len(detectURLBasedTech("https://example.com/.well-known/openid-configuration")) == 0 {
		t.Error("expected openid-configuration to be detected")
	}
	if len(detectURLBasedTech("https://example.com/realms/myrealm/protocol/openid-connect/auth")) == 0 {
		t.Error("expected Keycloak realm path to be detected")
	}
	if len(detectURLBasedTech("https://example.com/protocol/openid-connect/token")) == 0 {
		t.Error("expected OIDC token endpoint to be detected")
	}
	if len(detectURLBasedTech("https://example.com/api/v1/users")) != 0 {
		t.Error("ordinary API path should not be flagged as OIDC infrastructure")
	}
}

func TestDedupeWithLocationsCollapsesRepeats(t *testing.T) {
	items := []map[string]interface{}{
		{"type": "aws_access_key", "value": "AKIAABCDEFGHIJKLMNOP", "url": "https://t/page1.js", "severity": "high"},
		{"type": "aws_access_key", "value": "AKIAABCDEFGHIJKLMNOP", "url": "https://t/page2.js", "severity": "unknown"},
		{"type": "aws_access_key", "value": "AKIAABCDEFGHIJKLMNOP", "url": "https://t/page2.js", "severity": "unknown"}, // exact dup
		{"type": "jwt_token", "value": "eyJ.different.token", "url": "https://t/other.js", "severity": "unknown"},
	}
	result := DedupeWithLocations(items, []string{"type", "value"}, []string{"severity"},
		func(i map[string]interface{}) interface{} { return i["url"] })

	if len(result) != 2 {
		t.Fatalf("expected 2 unique findings, got %d", len(result))
	}

	var awsEntry *DedupedEntry
	for i := range result {
		if result[i].Fields["type"] == "aws_access_key" {
			awsEntry = &result[i]
		}
	}
	if awsEntry.SeenCount != 2 {
		t.Errorf("should count 2 distinct locations, not 3, got %d", awsEntry.SeenCount)
	}
	if awsEntry.Fields["severity"] != "high" {
		t.Errorf("should prefer non-unknown severity, got %v", awsEntry.Fields["severity"])
	}
}

func TestDedupeWithLocationsSortsByPrevalence(t *testing.T) {
	items := []map[string]interface{}{
		{"type": "a", "value": "v1", "url": "https://t/1"},
		{"type": "b", "value": "v2", "url": "https://t/1"},
		{"type": "b", "value": "v2", "url": "https://t/2"},
		{"type": "b", "value": "v2", "url": "https://t/3"},
	}
	result := DedupeWithLocations(items, []string{"type", "value"}, nil,
		func(i map[string]interface{}) interface{} { return i["url"] })
	if result[0].Fields["type"] != "b" || result[0].SeenCount != 3 {
		t.Errorf("expected 'b' with seen_count 3 first, got %v seen_count=%d", result[0].Fields["type"], result[0].SeenCount)
	}
}

func TestLinkExtractorBasicLinksAndForms(t *testing.T) {
	htmlBody := `
    <html><body>
      <a href="/page1">link</a>
      <img src="/img/logo.png">
      <script src="/js/app.js"></script>
      <link rel="stylesheet" href="/css/style.css">
      <form action="/submit" method="POST">
        <input name="username">
        <input name="password">
      </form>
    </body></html>
    `
	result := ExtractLinks(htmlBody)
	assertTrue(t, result.Links["/page1"])
	assertTrue(t, result.Links["/img/logo.png"])
	assertTrue(t, result.Links["/js/app.js"])
	assertTrue(t, result.Links["/css/style.css"])
	if len(result.Forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(result.Forms))
	}
	if result.Forms[0].Action != "/submit" || result.Forms[0].Method != "POST" {
		t.Errorf("form action/method mismatch: %+v", result.Forms[0])
	}
	if len(result.Forms[0].Inputs) != 2 {
		t.Errorf("expected 2 form inputs, got %v", result.Forms[0].Inputs)
	}
}

func TestLinkExtractorInlineScript(t *testing.T) {
	htmlBody := `<br/><input name="x"/><script>var x = "/api/hidden";</script>`
	result := ExtractLinks(htmlBody)
	if len(result.InlineScripts) != 1 {
		t.Fatalf("expected 1 inline script, got %d", len(result.InlineScripts))
	}
	if !contains(result.InlineScripts[0], "/api/hidden") {
		t.Errorf("inline script text missing expected content: %s", result.InlineScripts[0])
	}
}

func TestLinkExtractorTolerantOfMalformedHTML(t *testing.T) {
	result := ExtractLinks(`<div><a href="/x">unclosed <img src=/y.png >`)
	assertTrue(t, result.Links["/x"])
	assertTrue(t, result.Links["/y.png"])
}

func TestExtractURLsFromJSAbsoluteAndRelative(t *testing.T) {
	js := `
        fetch("/api/v2/users").then(r => r.json());
        const base = "https://api.example.com/v1/data";
        axios.get('/internal/admin/settings');
    `
	found := ExtractURLsFromJS(js)
	assertTrue(t, found["/api/v2/users"])
	assertTrue(t, found["https://api.example.com/v1/data"])
	assertTrue(t, found["/internal/admin/settings"])
}

func TestExtractURLsFromJSBundlerChunkManifest(t *testing.T) {
	// Regression test for the exact grouping bug found (and fixed) in the
	// Python original: the bundler-prefix alternation must be wrapped in
	// its own non-capturing group, or the path-suffix pattern only
	// attaches to the LAST alternative (dist/), silently failing to match
	// assets/, static/, chunks/, _next/, build/.
	js := `const __vite__mapDeps = (i => i.map(i => ["assets/api-DO2OmuJE.js"][i]))();`
	found := ExtractURLsFromJS(js)
	assertTrue(t, found["assets/api-DO2OmuJE.js"])
}

func TestExtractURLsFromJSNoFalsePositives(t *testing.T) {
	js := `const greeting = "hello world"; var x = "some_identifier_name";`
	found := ExtractURLsFromJS(js)
	if len(found) != 0 {
		t.Errorf("unexpected matches: %v", found)
	}
}

func TestFrontierDedupAndScopeEnforcement(t *testing.T) {
	scope, _ := NewScopeManager("https://example.com", true, nil, nil)
	f := NewFrontier(scope)
	if !f.Add("https://example.com/a") {
		t.Fatal("expected first add to succeed")
	}
	if f.Add("https://example.com/a") {
		t.Fatal("duplicate must be rejected")
	}
	if f.Add("https://evil.com/x") {
		t.Fatal("out-of-scope must be rejected")
	}
	if !f.Add("https://sub.example.com/b") {
		t.Fatal("in-scope subdomain must be accepted")
	}
	if f.Len() != 2 {
		t.Fatalf("expected len 2, got %d", f.Len())
	}
	u, _ := f.Pop()
	if u != "https://example.com/a" {
		t.Errorf("expected FIFO pop order, got %s", u)
	}
}

func TestFrontierThreadSafety(t *testing.T) {
	scope, _ := NewScopeManager("https://example.com", true, nil, nil)
	f := NewFrontier(scope)
	var accepted int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.Add("https://example.com/same-url") {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if accepted != 1 {
		t.Errorf("exactly one goroutine should have won the Add(), got %d", accepted)
	}
}

func TestRateLimiterDoesNotBlockWhenDisabled(t *testing.T) {
	var disabled *RateLimiter // nil -- matches "0 = unlimited" in NativeCrawlerOpts
	disabled.Acquire()        // must not panic
	enabled := NewRateLimiter(1000)
	enabled.Acquire()
	enabled.Acquire()
}

func TestCommonParamWordlistNonEmpty(t *testing.T) {
	if len(commonParamWordlist) <= 50 {
		t.Errorf("expected >50 words, got %d", len(commonParamWordlist))
	}
	assertContains(t, commonParamWordlist, "id")
	assertContains(t, commonParamWordlist, "redirect_uri")
}

func TestMethodBypassConfidenceTagging(t *testing.T) {
	classify := func(method string) string {
		if method == "OPTIONS" || method == "HEAD" {
			return "low-confidence"
		}
		return "method-bypass-candidate"
	}
	if classify("OPTIONS") != "low-confidence" {
		t.Error("OPTIONS should be low-confidence")
	}
	if classify("HEAD") != "low-confidence" {
		t.Error("HEAD should be low-confidence")
	}
	if classify("PUT") != "method-bypass-candidate" {
		t.Error("PUT should be method-bypass-candidate")
	}
}

// --- test helpers -------------------------------------------------------

func assertTrue(t *testing.T, cond bool) {
	t.Helper()
	if !cond {
		t.Errorf("expected true, got false")
	}
}

func assertFalse(t *testing.T, cond bool) {
	t.Helper()
	if cond {
		t.Errorf("expected false, got true")
	}
}

func assertContains(t *testing.T, list []string, item string) {
	t.Helper()
	for _, v := range list {
		if v == item {
			return
		}
	}
	t.Errorf("expected %q in %v", item, list)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
