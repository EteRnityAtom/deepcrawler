package main

// Secret detection: fixed signatures + generic entropy scanning.
// Direct port of deep_crawler.py's SECRET_SIGNATURES / scan_secrets /
// entropy_scan_text / shannon_entropy / is_likely_vendor_file.

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// SECRET_SIGNATURES -- identical patterns to the Python version. All of
// these are RE2-compatible as written (no lookaround/backreferences used
// anywhere in the hand-written set), so this is a direct, unmodified port.
var secretSignatures = map[string]string{
	"aws_access_key":       `AKIA[0-9A-Z]{16}`,
	"aws_secret_key":       `(?i)aws_?secret_?(access_?)?key\s*[=:]\s*["']([A-Za-z0-9/+=]{40})["']`,
	"google_api_key":       `AIza[0-9A-Za-z\-_]{35}`,
	"gcp_service_account":  `"type":\s*"service_account"`,
	"github_token":         `gh[pousr]_[A-Za-z0-9]{36,255}`,
	"slack_token":          `xox[baprs]-[0-9A-Za-z-]{10,72}`,
	"slack_webhook":        `https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}`,
	"stripe_key":           `(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,}`,
	"twilio_key":           `SK[0-9a-fA-F]{32}`,
	"sendgrid_key":         `SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`,
	"firebase_url":         `https://[a-z0-9-]+\.firebaseio\.com`,
	"jwt_token":            `eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}`,
	"private_key_block":    `-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----`,
	"generic_api_key":      `(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["']([a-zA-Z0-9_\-]{16,})["']`,
	"generic_secret":       `(?i)(?:secret|client_secret)\s*[=:]\s*["']([a-zA-Z0-9_\-]{16,})["']`,
	"basic_auth_in_url":    `https?://[a-zA-Z0-9_\-]{2,}:[^@/\s]{2,}@[a-zA-Z0-9.\-]+`,
	"db_connection_string": `(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql)://[^\s"']{6,}`,
	// Captured value is restricted to a password-plausible character set
	// (letters/digits/common symbols), NOT "any non-quote character" --
	// see the Python original's comment: on minified single-line JS,
	// [^"'] happily spans across an unrelated string boundary and
	// swallows raw JS syntax as the "password" (reproduced live against
	// swagger-ui-bundle.js). Anchoring the character class makes the
	// match fail immediately at the first )/,/? instead of swallowing
	// arbitrary code.
	"hardcoded_password": `(?i)(?:password|passwd|pwd)\s*[=:]\s*["']([a-zA-Z0-9_\-!@#$%^&*+.]{4,64})["']`,
}

// Strings that pattern-match generic_secret/generic_api_key but are
// near-certainly framework noise, not real secrets.
var falsePositiveValues = map[string]bool{
	"your_api_key": true, "your-api-key": true, "xxxxxxxx": true, "changeme": true,
	"placeholder": true, "example": true, "test": true, "null": true,
	"undefined": true, "none": true,
}

// Minified/bundled third-party libraries dominate false-positive volume --
// see the Python original's comment for the live-reproduced 111-false-
// positive case against swagger-ui-bundle.js.
var vendorFileRe = regexp.MustCompile(
	`(?i)(jquery|bootstrap|swagger-ui|react(-dom)?[.\-]|vendor|polyfill|` +
		`lodash|underscore|moment\.min|chart(\.min)?\.js|d3\.min|materialize|` +
		`foundation\.min|angular\.min|vue\.min|popper|font-?awesome|` +
		`highlight\.min|prism\.min|webpack-runtime|runtime~)[^/]*\.(?:js|css)(?:\?|$)`,
)

func isLikelyVendorFile(u string) bool {
	return vendorFileRe.MatchString(u)
}

// --- Nuclei signature import -------------------------------------------
//
// Loads the SAME nuclei_secret_signatures.json sidecar the Python version
// uses. Each pattern is re-validated against Go's RE2 engine (regexp.Compile)
// since RE2 does not support lookahead/lookbehind/backreferences that a few
// of the imported nuclei patterns may still use internally even after
// Python's own compile-filtering. This mirrors the exact same
// "try to compile, skip gracefully, keep going" architecture as the Python
// original (load_nuclei_signatures) -- the surviving pattern COUNT can
// differ slightly between the two languages purely due to this regex-engine
// difference; that is reported explicitly at load time, not hidden.
func loadNucleiSignatures(path string) map[string]string {
	signatures := make(map[string]string)

	data, err := os.ReadFile(path)
	if err != nil {
		return signatures
	}

	var raw map[string]struct {
		Name     string   `json:"name"`
		Severity string   `json:"severity"`
		Regexes  []string `json:"regexes"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return signatures
	}

	for key, entry := range raw {
		for i, rgx := range entry.Regexes {
			if _, err := regexp.Compile(rgx); err != nil {
				continue
			}
			name := "nuclei_" + key
			if i > 0 {
				name = name + "_" + itoa(i)
			}
			signatures[name] = rgx
		}
	}
	return signatures
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := []byte{}
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}

// A real secret value never legitimately contains JS/HTML syntax
// characters -- if it does, some capture group's context window matched
// across a string boundary. Applied as a universal safety net on top of
// every fixed-signature match, hand-written or nuclei-derived.
var implausibleValueCharsRe = regexp.MustCompile(`[<>{}();,` + "`" + `]`)

// No real credential/token is shorter than this -- see the Python
// original's comment: several imported nuclei templates have capture
// groups that are only safe in the narrow request/response context nuclei
// itself constrains them to; applied context-free they degenerate to
// matching single characters.
const minPlausibleSecretLength = 6

type compiledSignature struct {
	name string
	re   *regexp.Regexp
}

var compiledSecretSignatures []compiledSignature
var allSecretSignatures map[string]string // exposed for tests, mirrors ALL_SECRET_SIGNATURES

func initSecretSignatures(nucleiSignaturesPath string) {
	allSecretSignatures = make(map[string]string)
	for k, v := range secretSignatures {
		allSecretSignatures[k] = v
	}
	for k, v := range loadNucleiSignatures(nucleiSignaturesPath) {
		allSecretSignatures[k] = v
	}

	// Sorted iteration for deterministic ordering (map iteration in Go is
	// randomized) -- doesn't affect correctness, but keeps output stable
	// across runs for diffing/debugging.
	names := make([]string, 0, len(allSecretSignatures))
	for k := range allSecretSignatures {
		names = append(names, k)
	}
	sort.Strings(names)

	compiledSecretSignatures = nil
	for _, name := range names {
		re, err := regexp.Compile(allSecretSignatures[name])
		if err != nil {
			continue
		}
		compiledSecretSignatures = append(compiledSecretSignatures, compiledSignature{name: name, re: re})
	}
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0.0
	}
	counts := make(map[rune]int)
	for _, c := range s {
		counts[c]++
	}
	n := float64(len(s))
	var entropy float64
	for _, count := range counts {
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

var entropyCandidateRe = regexp.MustCompile(`["']([A-Za-z0-9_\-/+=]{20,100})["']`)
var identifierLikeRe = regexp.MustCompile(`^[a-z]+(?:_[a-z]+)+$`)
var mimeLikeRe = regexp.MustCompile(`(?i)^[a-z]+/[a-z0-9.+\-]+$`)

// Threshold for isSequentialAlphabetLike: real random tokens (base64/hex
// secrets) have each character chosen independently, so the chance any
// given adjacent pair happens to be consecutive code points is ~1/16-1/64 --
// a genuine random token essentially never exceeds ~15-20% "ascending"
// pairs by chance. A literal alphabet-definition constant is composed
// almost entirely of such runs (broken only at the A-Z/a-z/0-9/symbol
// category boundaries), so it sits far above this threshold; 0.5 leaves a
// wide, safe margin on both sides.
const sequentialAlphabetRatioThreshold = 0.5

// isSequentialAlphabetLike rejects base64/hex/radix ALPHABET DEFINITION
// constants (e.g. the literal string
// "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" that
// CryptoJS-style encoding libraries embed verbatim in their own source) --
// these are high-entropy, character-class-mixed, and pass every other
// filter, but they're a hardcoded LIBRARY CONSTANT, not a secret.
// Reproduced live against a real production JS bundle
// (abgcareers.peoplestrong.com)'s base64 encoder: scored entropy 6.0 and
// passed every prior check. Detected by the fact that an alphabet constant
// is composed almost entirely of sequentially-ascending character codes,
// which a genuinely random secret token essentially never is.
func isSequentialAlphabetLike(token string) bool {
	if len(token) < 8 {
		return false
	}
	runes := []rune(token)
	ascending := 0
	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1]+1 {
			ascending++
		}
	}
	return float64(ascending)/float64(len(runes)-1) > sequentialAlphabetRatioThreshold
}

type EntropyFinding struct {
	Value   string  `json:"value"`
	Entropy float64 `json:"entropy"`
}

// entropyScanText: catch custom/unknown secret formats that fixed regexes
// miss. Direct port of entropy_scan_text.
func entropyScanText(text string, minEntropy float64) []EntropyFinding {
	var findings []EntropyFinding
	seen := make(map[string]bool)

	for _, m := range entropyCandidateRe.FindAllStringSubmatch(text, -1) {
		token := m[1]
		if seen[token] || falsePositiveValues[strings.ToLower(token)] {
			continue
		}
		seen[token] = true

		distinctChars := make(map[rune]bool)
		for _, c := range token {
			distinctChars[c] = true
		}
		if len(distinctChars) < 8 {
			continue
		}
		if identifierLikeRe.MatchString(token) || mimeLikeRe.MatchString(token) {
			continue
		}
		if isSequentialAlphabetLike(token) {
			continue
		}

		hasDigit, hasUpper, hasLower, hasSymbol := false, false, false, false
		for _, c := range token {
			switch {
			case c >= '0' && c <= '9':
				hasDigit = true
			case c >= 'A' && c <= 'Z':
				hasUpper = true
			case c >= 'a' && c <= 'z':
				hasLower = true
			case strings.ContainsRune("+/=_-", c):
				hasSymbol = true
			}
		}
		if !(hasDigit || (hasUpper && hasLower) || (hasSymbol && hasUpper)) {
			continue
		}

		ent := shannonEntropy(token)
		if ent >= minEntropy {
			findings = append(findings, EntropyFinding{Value: token, Entropy: roundTo2(ent)})
		}
	}
	return findings
}

func roundTo2(f float64) float64 {
	return math.Round(f*100) / 100
}

// SecretMatch is either a plain string value (fixed-signature hit) or an
// EntropyFinding (high_entropy_string hit) -- mirrors Python's mixed
// list-of-(str|dict) shape for the "high_entropy_string" key.
type SecretMatch struct {
	StringValue string
	Entropy     *EntropyFinding
}

func (m SecretMatch) Value() string {
	if m.Entropy != nil {
		return m.Entropy.Value
	}
	return m.StringValue
}

// ScanSecrets: run fixed signatures (hand-written + nuclei-derived) +
// entropy scan over one blob of text. Direct port of scan_secrets, with
// the same max_matches_per_signature runaway-output guard.
func ScanSecrets(text string, maxMatchesPerSignature int) map[string][]SecretMatch {
	findings := make(map[string][]SecretMatch)

	for _, sig := range compiledSecretSignatures {
		matchCount := 0
		matches := sig.re.FindAllStringSubmatch(text, -1)
		seenValues := make(map[string]bool)
		for _, m := range matches {
			if matchCount >= maxMatchesPerSignature {
				break
			}
			var value string
			if len(m) > 1 && m[1] != "" {
				value = m[1]
			} else {
				value = m[0]
			}
			if value == "" {
				continue
			}
			if falsePositiveValues[strings.ToLower(value)] {
				continue
			}
			if implausibleValueCharsRe.MatchString(value) {
				continue
			}
			if len(value) < minPlausibleSecretLength {
				continue
			}
			matchCount++
			if !seenValues[value] {
				seenValues[value] = true
				findings[sig.name] = append(findings[sig.name], SecretMatch{StringValue: value})
			}
		}
	}

	entropyHits := entropyScanText(text, 4.3)
	if len(entropyHits) > 0 {
		var matches []SecretMatch
		for i := range entropyHits {
			matches = append(matches, SecretMatch{Entropy: &entropyHits[i]})
		}
		findings["high_entropy_string"] = matches
	}

	return findings
}

func nucleiSignaturesDefaultPath(exeDir string) string {
	return filepath.Join(exeDir, "nuclei_secret_signatures.json")
}
