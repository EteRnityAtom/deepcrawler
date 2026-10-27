package main

// robots.txt + sitemap.xml discovery -- a standard recon technique this
// tool was missing. Disallow/Allow directives in robots.txt frequently
// reveal paths the site owner specifically doesn't want indexed (admin
// panels, staging areas, internal tools) -- exactly the kind of thing
// worth a security crawler's attention even though a search-engine
// crawler is meant to skip them. Sitemap.xml (whether referenced from
// robots.txt or found at the conventional /sitemap.xml location) often
// lists URLs no longer linked from the live site's navigation.

import (
	"encoding/xml"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var sitemapDirectiveRe = regexp.MustCompile(`(?i)^\s*sitemap:\s*(\S+)`)
var disallowAllowDirectiveRe = regexp.MustCompile(`(?i)^\s*(?:dis)?allow:\s*(\S*)`)

// urlSet / sitemapIndex mirror the two possible root elements of a sitemap
// XML document (a plain list of pages, or an index pointing at further
// per-section sitemaps -- common on large sites).
type sitemapURLSet struct {
	XMLName xml.Name `xml:"urlset"`
	URLs    []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
}

type sitemapIndex struct {
	XMLName  xml.Name `xml:"sitemapindex"`
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

// RobotsAndSitemapDiscovery fetches {target}/robots.txt, extracts every
// Disallow/Allow path and every referenced Sitemap: URL, then recursively
// fetches and parses each sitemap (following sitemap-index chains up to
// one level deep, which covers the overwhelming majority of real-world
// setups without risking an unbounded recursive-sitemap loop). Also tries
// the conventional /sitemap.xml location directly, since not every site
// references it from robots.txt. All discovered URLs still pass through
// the caller's normal scope check before ever being fetched.
func RobotsAndSitemapDiscovery(targetURL string, scope *ScopeManager, timeoutSec int) map[string]bool {
	found := make(map[string]bool)
	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}

	robotsURL := resolveRef(targetURL, "/robots.txt")
	sitemapURLs := make(map[string]bool)

	if body, ok := fetchText(client, robotsURL); ok {
		for _, line := range strings.Split(body, "\n") {
			if m := sitemapDirectiveRe.FindStringSubmatch(line); m != nil {
				sitemapURLs[resolveRef(targetURL, strings.TrimSpace(m[1]))] = true
				continue
			}
			if m := disallowAllowDirectiveRe.FindStringSubmatch(line); m != nil {
				path := strings.TrimSpace(m[1])
				if path == "" || path == "/" {
					continue
				}
				full := resolveRef(targetURL, path)
				if scope.InScope(full) {
					found[full] = true
				}
			}
		}
	}

	// Conventional fallback location, tried regardless of what robots.txt said.
	sitemapURLs[resolveRef(targetURL, "/sitemap.xml")] = true

	visitedSitemaps := make(map[string]bool)
	for sm := range sitemapURLs {
		fetchSitemap(client, sm, scope, found, visitedSitemaps, 0)
	}

	return found
}

func fetchSitemap(client *http.Client, sitemapURL string, scope *ScopeManager,
	found map[string]bool, visited map[string]bool, depth int) {
	if depth > 1 || visited[sitemapURL] {
		return // one level of sitemap-index nesting is enough for the real-world case; avoid unbounded recursion
	}
	visited[sitemapURL] = true

	body, ok := fetchTextRaw(client, sitemapURL)
	if !ok {
		return
	}

	var index sitemapIndex
	if xml.Unmarshal(body, &index) == nil && len(index.Sitemaps) > 0 {
		for _, s := range index.Sitemaps {
			fetchSitemap(client, s.Loc, scope, found, visited, depth+1)
		}
		return
	}

	var set sitemapURLSet
	if xml.Unmarshal(body, &set) == nil {
		for _, u := range set.URLs {
			if scope.InScope(u.Loc) {
				found[u.Loc] = true
			}
		}
	}
}

func fetchText(client *http.Client, url string) (string, bool) {
	b, ok := fetchTextRaw(client, url)
	if !ok {
		return "", false
	}
	return string(b), true
}

func fetchTextRaw(client *http.Client, url string) ([]byte, bool) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, false
	}
	return body, true
}
