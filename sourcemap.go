package main

// Source map discovery and recovery -- a well-known, high-value recon
// technique this tool was missing. Modern bundlers (webpack, Vite, esbuild,
// Angular CLI) commonly ship a `//# sourceMappingURL=file.js.map` comment
// at the end of every JS file, and many production deployments leave the
// referenced .map file publicly accessible by mistake (or deliberately,
// for error-tracking services). A source map's `sourcesContent` field, when
// present, contains the ENTIRE ORIGINAL SOURCE -- unminified, with real
// variable/function names, comments, and file structure -- which is far
// more revealing for secret-scanning and logic-flaw detection than the
// minified bundle ever is. Exposed source maps are themselves a recognized
// finding class (CWE-540-adjacent: source code disclosure).

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Matches the trailing sourceMappingURL comment in either // or /* */ form,
// which is how every major bundler emits it.
var sourceMappingURLRe = regexp.MustCompile(`(?://|/\*)[#@]\s*sourceMappingURL=(\S+?)(?:\s*\*/)?\s*$`)

type sourceMapFile struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
	File           string   `json:"file"`
}

// ExtractSourceMappingURL returns the raw (not yet resolved) sourceMappingURL
// reference from a JS file's content, or "" if none is present. Data URIs
// (inline source maps, `data:application/json;base64,...`) are
// deliberately not treated as "discovered" -- they don't reveal anything
// an attacker didn't already have (the map is already embedded in the same
// file being analyzed).
func ExtractSourceMappingURL(jsBody string) string {
	lines := strings.Split(jsBody, "\n")
	// The directive is conventionally the last non-empty line, but scan
	// from the end defensively in case of trailing whitespace/newlines.
	for i := len(lines) - 1; i >= 0 && i >= len(lines)-5; i-- {
		if m := sourceMappingURLRe.FindStringSubmatch(lines[i]); m != nil {
			ref := strings.TrimSpace(m[1])
			if strings.HasPrefix(ref, "data:") {
				return ""
			}
			return ref
		}
	}
	return ""
}

// ParseSourceMap extracts every original source file's content from a
// fetched .map file's JSON body. Returns a map of {original filename (or a
// synthetic name if unavailable) -> source text}, covering only entries
// that actually have sourcesContent embedded (many production source maps
// omit it deliberately to avoid exactly this kind of exposure, in which
// case there is nothing recoverable beyond the sources list itself).
func ParseSourceMap(mapBody []byte) (map[string]string, error) {
	var sm sourceMapFile
	if err := json.Unmarshal(mapBody, &sm); err != nil {
		return nil, err
	}
	result := make(map[string]string)
	for i, content := range sm.SourcesContent {
		if content == "" {
			continue
		}
		name := sm.File
		if i < len(sm.Sources) && sm.Sources[i] != "" {
			name = sm.Sources[i]
		}
		if name == "" {
			name = "source_" + itoa(i)
		}
		result[name] = content
	}
	return result, nil
}
