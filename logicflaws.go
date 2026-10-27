package main

// Application logic flaw heuristics (JS/HTML static analysis).
// Direct port of deep_crawler.py's LOGIC_FLAW_PATTERNS / scan_logic_flaws.
// All patterns are RE2-compatible as written (no lookaround needed).

import (
	"regexp"
	"strings"
)

type logicFlawDef struct {
	pattern  *regexp.Regexp
	severity string
	note     string
}

var logicFlawPatterns = map[string]logicFlawDef{
	"client_side_only_validation": {
		regexp.MustCompile(`(?:if|while)\s*\([^)]*\.length\s*[<>=]`),
		"low",
		"Length/format check appears to run only in the browser; confirm the server repeats it.",
	},
	"disabled_security_check": {
		regexp.MustCompile(`(?i)(?:disable[d]?|skip|bypass|ignore)[A-Za-z_]*\s*[=:(]\s*(?:true|1)?.*?(?:auth|csrf|xss|security|validation)`),
		"medium",
		"A security check looks like it can be toggled off.",
	},
	"debug_flag_enabled": {
		regexp.MustCompile(`(?i)(?:debug|isDebug|DEV|DEVELOPMENT)\s*[=:]\s*(?:true|1)\b`),
		"medium",
		"Debug/dev flag present in shipped code; may unlock verbose errors or hidden routes.",
	},
	// Captured value restricted to a password-plausible character set, NOT
	// "any non-quote character" -- see secrets.go's hardcoded_password
	// comment for the original reasoning (this exact pattern independently
	// had the same unrestricted-[^"'] bug and reproduced the same class of
	// false positive live: an i18n error-message dictionary entry
	// `Password:"Invalid password."` matched as a HIGH-severity hardcoded
	// credential purely because the value contained neither quote char).
	// A space is deliberately absent from the allowed set: it's exactly
	// what separates a real single-token credential from a sentence.
	"hardcoded_credential": {
		regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret)\s*[=:]\s*["']([a-zA-Z0-9_\-!@#$%^&*+.]{4,64})["']`),
		"high",
		"Credential-shaped literal hardcoded in client code.",
	},
	"weak_crypto_on_secret": {
		regexp.MustCompile(`(?i)(?:md5|sha1)\s*\([^)]*(?:password|token|secret)`),
		"medium",
		"Weak hash algorithm applied to something sensitive client-side.",
	},
	"eval_or_dynamic_exec": {
		regexp.MustCompile(`\b(?:eval|new Function)\s*\(`),
		"medium",
		"Dynamic code execution sink; check what feeds it.",
	},
	"dom_xss_sink": {
		regexp.MustCompile(`\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\(`),
		"medium",
		"DOM XSS sink; check for attacker-controlled input reaching it.",
	},
	"todo_fixme_security": {
		regexp.MustCompile(`(?i)(?://|/\*).{0,40}(?:TODO|FIXME|HACK|XXX).{0,80}(?:auth|security|password|token|validat)`),
		"low",
		"Developer left a security-relevant TODO/FIXME.",
	},
	"client_side_price_or_role": {
		regexp.MustCompile(`(?i)(?:price|amount|total|role|isAdmin|is_admin)\s*[=:]\s*(?:req\.|params\.|query\.|this\.state\.|this\.props\.)`),
		"high",
		"Business-critical value (price/role) appears sourced from client-controlled state.",
	},
}

type LogicFlaw struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Note     string `json:"note"`
	Snippet  string `json:"snippet"`
	Source   string `json:"source"`
}

var postMessageListenerRe = regexp.MustCompile(`addEventListener\(\s*["']message["']`)

// postMessageOriginCheckWindow is how far past the listener registration to
// look for an origin check. Real-world handlers vary widely in structure
// (inline arrow function vs. named handler defined elsewhere in the same
// scope, an early-return guard vs. a wrapping if), so this is deliberately
// generous rather than tightly scoped to "immediately next line".
const postMessageOriginCheckWindow = 400

// checkPostMessageOriginGuard replaces a naive "does addEventListener(
// 'message') appear anywhere" scan (which flagged EVERY postMessage
// listener regardless of whether it was already guarded, since almost
// every SPA framework/analytics/payment-widget bundle registers at least
// one) with windowed context analysis: only flag listeners with no
// ".origin" reference anywhere in the following stretch of code, which is
// a real signal the origin most likely was never checked. This still
// isn't proof -- a check could reference origin through an aliased
// variable, or exist further away than the window -- so it stays a
// candidate ("verify manually"), just a far less noisy one.
func checkPostMessageOriginGuard(text, sourceURL string) []LogicFlaw {
	var flaws []LogicFlaw
	for _, loc := range postMessageListenerRe.FindAllStringIndex(text, -1) {
		end := loc[1] + postMessageOriginCheckWindow
		if end > len(text) {
			end = len(text)
		}
		window := text[loc[1]:end]
		if strings.Contains(window, ".origin") {
			continue // an origin check is plausibly present nearby -- not flagged
		}
		// Snippet stays the short literal match (not the context window
		// used for the origin check above) -- every other flaw type's
		// snippet is a short, stable literal, which is exactly what
		// DedupeWithLocations groups occurrences by (type, snippet). A
		// wide context window would be different at every call site,
		// defeating grouping and flooding output with near-duplicate
		// mega-snippets instead of one entry with N locations.
		flaws = append(flaws, LogicFlaw{
			Type:     "postmessage_no_origin_check",
			Severity: "medium",
			Note:     "postMessage listener found with no event.origin check in the following code -- verify manually; an unchecked origin lets any page frame/window post attacker-controlled data into this handler.",
			Snippet:  text[loc[0]:loc[1]],
			Source:   sourceURL,
		})
	}
	return flaws
}

func ScanLogicFlaws(text, sourceURL string) []LogicFlaw {
	var flaws []LogicFlaw
	for flawType, def := range logicFlawPatterns {
		for _, m := range def.pattern.FindAllString(text, -1) {
			snippet := m
			if len(snippet) > 160 {
				snippet = snippet[:160]
			}
			flaws = append(flaws, LogicFlaw{
				Type: flawType, Severity: def.severity, Note: def.note,
				Snippet: snippet, Source: sourceURL,
			})
		}
	}
	flaws = append(flaws, checkPostMessageOriginGuard(text, sourceURL)...)
	return flaws
}
