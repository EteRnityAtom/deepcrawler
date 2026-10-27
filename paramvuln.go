package main

// Parameter -> suggested vulnerability class heuristics.
// Direct port of deep_crawler.py's PARAM_VULN_KEYWORDS / tokenize_param_name
// / suggest_vuln_classes.
//
// NOTE ON REGEX-ENGINE DIFFERENCE: Python's _CAMEL_BOUNDARY_RE used
// lookbehind+lookahead ((?<=[a-z0-9])(?=[A-Z])), which Go's RE2 engine
// (regexp package) cannot compile at all -- RE2 deliberately excludes
// backreferences and lookaround to guarantee linear-time matching. This is
// replaced below with an explicit character-by-character scan
// (insertCamelBoundaries) that inserts the identical zero-width boundary
// the lookaround regex found -- same INPUT/OUTPUT behavior, different
// mechanism. This is the single largest logic-preserving deviation
// required by the language port; everything else compiles as literal RE2.

import (
	"regexp"
	"strings"
)

type vulnKeywordSet struct {
	keywords map[string]bool
	classes  []string
}

var paramVulnKeywords = []vulnKeywordSet{
	{setOf("id", "uid", "userid", "orderid", "accountid", "invoiceid", "docid"),
		[]string{"IDOR", "Authorization bypass"}},
	{setOf("url", "redirect", "return", "next", "callback", "continue", "dest"),
		[]string{"Open Redirect", "SSRF"}},
	{setOf("file", "path", "dir", "folder", "template", "include", "document"),
		[]string{"LFI", "Path Traversal"}},
	{setOf("q", "query", "search", "filter", "sort", "orderby", "name"),
		[]string{"SQLi", "NoSQLi"}},
	{setOf("cmd", "exec", "command", "run", "ping", "host"),
		[]string{"Command Injection", "SSRF"}},
	{setOf("email", "username", "comment", "message", "bio", "title", "content"),
		[]string{"XSS (reflected/stored)"}},
	{setOf("price", "amount", "qty", "quantity", "total", "discount", "coupon"),
		[]string{"Business logic - price/quantity manipulation"}},
	{setOf("role", "admin", "isadmin", "permission", "permissions", "scope", "accesslevel"),
		[]string{"Privilege escalation", "Mass assignment"}},
	{setOf("token", "otp", "code", "reset", "verify"),
		[]string{"Auth bypass", "Brute force / rate-limit"}},
	{setOf("callback", "jsonp"),
		[]string{"JSONP injection"}},
	{setOf("xml", "soap"),
		[]string{"XXE"}},
}

func setOf(items ...string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, i := range items {
		s[i] = true
	}
	return s
}

var nonAlnumRe = regexp.MustCompile(`[^A-Za-z0-9]+`)

// insertCamelBoundaries replicates (?<=[a-z0-9])(?=[A-Z]) -> '_' exactly:
// for every position where the previous rune is lowercase-or-digit and the
// current rune is uppercase, insert an underscore boundary.
func insertCamelBoundaries(s string) string {
	runes := []rune(s)
	var sb strings.Builder
	sb.Grow(len(s) + 4)
	for i, r := range runes {
		if i > 0 {
			prev := runes[i-1]
			prevIsLowerOrDigit := (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9')
			curIsUpper := r >= 'A' && r <= 'Z'
			if prevIsLowerOrDigit && curIsUpper {
				sb.WriteByte('_')
			}
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// TokenizeParamName: snake_case, kebab-case, and camelCase -> a set of
// lowercase tokens.
func TokenizeParamName(name string) map[string]bool {
	normalized := insertCamelBoundaries(name)
	normalized = nonAlnumRe.ReplaceAllString(normalized, "_")
	tokens := make(map[string]bool)
	for _, t := range strings.Split(normalized, "_") {
		if t != "" {
			tokens[strings.ToLower(t)] = true
		}
	}
	return tokens
}

func SuggestVulnClasses(paramName string) []string {
	tokens := TokenizeParamName(paramName)
	suggestions := make(map[string]bool)
	for _, kw := range paramVulnKeywords {
		for t := range tokens {
			if kw.keywords[t] {
				for _, c := range kw.classes {
					suggestions[c] = true
				}
				break
			}
		}
	}
	if len(suggestions) == 0 {
		return []string{"Generic input validation"}
	}
	result := make([]string, 0, len(suggestions))
	for c := range suggestions {
		result = append(result, c)
	}
	sortStrings(result)
	return result
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
