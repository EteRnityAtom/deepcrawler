package main

// URL resolution (bundler chunk-manifest aware).
// Direct port of deep_crawler.py's resolve_discovered_url.

import (
	"net/url"
	"strings"
)

var bundlerRootRelativePrefixes = []string{"assets/", "static/", "chunks/", "_next/", "build/", "dist/"}

// ResolveDiscoveredURL resolves a URL/path string found inside crawled
// JS/HTML content.
//
//   - Absolute URLs and root-relative paths (leading '/') resolve normally
//     -- baseHref never applies to these, per the HTML/URL spec.
//
//   - Everything else is a genuinely relative reference. Per spec, ALL
//     relative HTML-attribute references (href/src/action/...) AND all
//     relative strings passed to runtime Window/Document-context JS APIs
//     (fetch, XMLHttpRequest.open, axios.get, ...) resolve against the
//     DOCUMENT'S BASE URL -- which is the page's own URL, UNLESS the page
//     declares <base href="...">, in which case EVERY such reference
//     resolves against that instead, regardless of the referencing file's
//     own location. If baseHref is non-empty, it is used for any relative
//     path that isn't absolute/root-relative.
//
//     Reproduced live against a real Angular production app
//     (abgcareers.peoplestrong.com): its compiled bundle emits
//     `<script src="chunk-X.js">` (bare, no leading slash) relying on the
//     page's own `<base href="/">` to resolve it to `/chunk-X.js`. Without
//     base-href awareness, naive sibling-relative resolution mis-resolves
//     this to a nested path (a 404) whenever the referencing page's own
//     URL has any path segments -- confirmed via direct curl: the true
//     `/chunk-X.js` returned 200, the mis-resolved sibling-relative guess
//     returned 404.
//
//   - If baseHref is empty (not yet observed), a bare path matching a
//     known bundler chunk-manifest prefix still resolves against the site
//     root as a fallback approximation (the original, narrower fix for the
//     same underlying class of bug, kept as a safety net for JS files
//     fetched before any HTML page's <base> tag was ever seen).
//
//   - Failing all of the above, resolve relative to the referencing file.
func ResolveDiscoveredURL(siteRoot, referencingURL, rawPath, baseHref string) string {
	if strings.HasPrefix(rawPath, "http://") || strings.HasPrefix(rawPath, "https://") ||
		strings.HasPrefix(rawPath, "ws://") || strings.HasPrefix(rawPath, "wss://") ||
		strings.HasPrefix(rawPath, "/") {
		return resolveRef(referencingURL, rawPath)
	}
	if baseHref != "" {
		return resolveRef(baseHref, rawPath)
	}
	for _, prefix := range bundlerRootRelativePrefixes {
		if strings.HasPrefix(rawPath, prefix) {
			return resolveRef(siteRoot, "/"+rawPath)
		}
	}
	return resolveRef(referencingURL, rawPath)
}

func resolveRef(base, ref string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return baseURL.ResolveReference(refURL).String()
}
