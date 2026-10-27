package main

// Native JS URL extraction (replaces jsluice's AST-based extraction, same
// role as deep_crawler.py's extract_urls_from_js). Deliberately
// conservative and quote-anchored (not a bare substring search) to avoid
// matching arbitrary non-URL strings.

import (
	"regexp"
	"strings"
)

// Also matches ws(s):// -- WebSocket endpoints embedded in bundled SPA JS
// (chat, live-update, real-time-notification code) are a legitimate
// recon target in their own right and frequently carry weaker
// authz/authn than the sibling REST API, but were previously invisible to
// this scanner entirely since the regex only recognized http(s).
var jsAbsoluteURLRe = regexp.MustCompile(`(?:https?|wss?)://[a-zA-Z0-9][a-zA-Z0-9\-.]*(?::[0-9]+)?(?:/[^\s'"<>\\` + "`" + `]*)?`)

// JS_ROOT_RELATIVE_PATH_RE in Python used a negative lookahead, (?!/), to
// exclude protocol-relative "//host/path" URLs from matching as a plain
// root-relative path (those need different resolution -- they're
// equivalent to "https://host/path", not a same-site path). RE2 cannot
// express that lookahead, so the pattern here omits it and the exclusion
// is applied explicitly in ExtractURLsFromJS below (skip any match whose
// captured group starts with "//") -- identical filtering result, moved
// from regex to plain code.
var jsRootRelativePathRe = regexp.MustCompile(`["'](/[a-zA-Z0-9_\-./%]+(?:\?[a-zA-Z0-9_\-=&%.]*)?)["']`)

var bundlerAlternation = strings.Join(func() []string {
	out := make([]string, len(bundlerRootRelativePrefixes))
	for i, p := range bundlerRootRelativePrefixes {
		out[i] = regexp.QuoteMeta(p)
	}
	return out
}(), "|")

// The alternation MUST be its own non-capturing group -- see the Python
// original's comment on _BUNDLER_ALTERNATION for the exact grouping bug
// this guards against (without it, the path-suffix pattern only attaches
// to the LAST alternative, silently failing to match "assets/", "static/",
// etc; this was caught by that project's own test suite before ever
// running live, and independently confirmed still broken -- as the
// unrelated resolveURL bug, not this specific regex form -- in another
// Go-based crawler compared against it).
var jsBareBundlerPathRe = regexp.MustCompile(`["']((?:` + bundlerAlternation + `)[a-zA-Z0-9_\-./]+)["']`)

// ExtractURLsFromJS: native replacement for jsluice's URL extraction.
// Returns raw path/URL strings (not yet resolved against a base -- caller
// must call ResolveDiscoveredURL).
func ExtractURLsFromJS(text string) map[string]bool {
	found := make(map[string]bool)

	for _, m := range jsAbsoluteURLRe.FindAllString(text, -1) {
		found[strings.TrimRight(m, ".,;)")] = true
	}

	for _, m := range jsRootRelativePathRe.FindAllStringSubmatch(text, -1) {
		captured := m[1]
		if strings.HasPrefix(captured, "//") {
			continue // protocol-relative URL -- excluded by the lookahead in the Python original
		}
		found[captured] = true
	}

	for _, m := range jsBareBundlerPathRe.FindAllStringSubmatch(text, -1) {
		found[m[1]] = true
	}

	return found
}
