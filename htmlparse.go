package main

// Native HTML link/form extraction (replaces katana's HTML parsing, same
// role as deep_crawler.py's LinkExtractor). Python used stdlib
// html.parser.HTMLParser; Go's standard library has no HTML tokenizer, so
// this uses golang.org/x/net/html -- the official Go-team-maintained
// extended-stdlib package (the same one goquery itself is built on), not a
// third-party replacement. Tolerant of malformed markup exactly like
// Python's html.parser, matching the original design intent.

import (
	"io"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

var urlAttrs = map[string]bool{
	"href": true, "src": true, "action": true, "formaction": true,
	"data": true, "poster": true, "background": true,
	// data-* attributes frontend code commonly uses to stash a URL for
	// vanilla-JS/lazy-load libraries to read at runtime -- real recon
	// surface (a data-endpoint/data-api value is frequently an actual
	// backend route baked straight into server-rendered markup) that a
	// scanner limited to standard link/media attributes would never see,
	// since these never appear as string literals in any JS file at all.
	"data-src": true, "data-href": true, "data-url": true,
	"data-endpoint": true, "data-action": true, "data-api": true,
	"data-remote": true,
}

type FormDef struct {
	Action string
	Method string
	Inputs []string
}

type LinkExtractResult struct {
	Links         map[string]bool
	Forms         []FormDef
	Title         string
	BaseHref      string
	InlineScripts []string
	Comments      []string
}

var metaRefreshURLRe = regexp.MustCompile(`(?i)url\s*=\s*(.+)`)

// ExtractLinks walks one HTML document and collects every attribute that
// can carry a navigable/fetchable URL, plus form definitions and inline
// <script> text for further JS analysis -- direct behavioral port of
// LinkExtractor.
func ExtractLinks(body string) LinkExtractResult {
	result := LinkExtractResult{Links: make(map[string]bool)}
	tokenizer := html.NewTokenizer(strings.NewReader(body))

	var currentForm *FormDef
	inScript := false
	inTitle := false
	var scriptBuf strings.Builder

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			if tokenizer.Err() != io.EOF {
				continue // tolerate malformed markup, never abort -- same posture as Python's error() override
			}
			break
		}

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := tokenizer.Token()
			attrs := make(map[string]string)
			for _, a := range tok.Attr {
				attrs[strings.ToLower(a.Key)] = a.Val
			}

			for attrName := range urlAttrs {
				if v, ok := attrs[attrName]; ok && strings.TrimSpace(v) != "" {
					result.Links[strings.TrimSpace(v)] = true
				}
			}

			if tok.Data == "meta" && strings.ToLower(attrs["http-equiv"]) == "refresh" {
				if m := metaRefreshURLRe.FindStringSubmatch(attrs["content"]); m != nil {
					u := strings.Trim(strings.TrimSpace(m[1]), `'"`)
					result.Links[u] = true
				}
			}

			switch tok.Data {
			case "base":
				// <base href="..."> changes the resolution base for every
				// OTHER relative reference in the document -- captured
				// here (first occurrence wins, matching real browser
				// behavior which only honors the first <base> element)
				// and used by the caller via ResolveDiscoveredURL's
				// baseHref parameter.
				if result.BaseHref == "" {
					if href := strings.TrimSpace(attrs["href"]); href != "" {
						result.BaseHref = href
					}
				}
			case "form":
				method := strings.ToUpper(attrs["method"])
				if method == "" {
					method = "GET"
				}
				currentForm = &FormDef{Action: attrs["action"], Method: method}
			case "input", "select", "textarea", "button":
				if currentForm != nil {
					if name, ok := attrs["name"]; ok && name != "" {
						currentForm.Inputs = append(currentForm.Inputs, name)
					}
				}
			case "script":
				if tt == html.StartTagToken {
					inScript = true
					scriptBuf.Reset()
				}
			case "title":
				if tt == html.StartTagToken {
					inTitle = true
				}
			}

		case html.EndTagToken:
			tok := tokenizer.Token()
			switch tok.Data {
			case "form":
				if currentForm != nil {
					result.Forms = append(result.Forms, *currentForm)
					currentForm = nil
				}
			case "script":
				inScript = false
				if scriptBuf.Len() > 0 {
					result.InlineScripts = append(result.InlineScripts, scriptBuf.String())
				}
			case "title":
				inTitle = false
			}

		case html.TextToken:
			text := string(tokenizer.Text())
			if inScript {
				scriptBuf.WriteString(text)
			} else if inTitle && result.Title == "" {
				result.Title = strings.TrimSpace(text)
			}

		case html.CommentToken:
			// Commented-out markup and developer notes ("<!-- <a
			// href=/admin-debug> -->", "<!-- TODO: remove before prod,
			// hits /internal/api -->") are a well-known place leftover
			// debug links, credentials, and internal endpoint references
			// get accidentally shipped. The tokenizer would otherwise
			// silently skip comment content entirely.
			result.Comments = append(result.Comments, string(tokenizer.Text()))
		}
	}

	return result
}
