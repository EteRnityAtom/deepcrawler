package main

// Native crawler. Direct port of deep_crawler.py's NativeCrawler class.

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type NativeCrawler struct {
	targetURL       string
	outputDir       string
	maxURLs         *int // nil = unbounded, matches Python's max_urls=None
	concurrency     int
	rateLimiter     *RateLimiter
	proxy           string
	timeout         time.Duration
	passive         bool
	paramsDiscovery bool
	resume          bool
	maxRuntimeSec   *float64 // nil = unbounded
	statusInterval  float64
	// Headless-rendering (--render-js): renderer is nil when the feature is
	// off (the default) or failed to start (missing browser) -- both cases
	// are handled identically by every call site, as "static HTML only".
	renderer *Renderer

	scope            *ScopeManager
	client           *http.Client
	clientNoRedirect *http.Client

	workDir   string
	statePath string

	stateMu           sync.Mutex
	visited           map[string]bool
	endpoints         map[string]bool
	paths             map[string]bool
	jsFiles           map[string]bool
	forms             []map[string]interface{}
	sensitiveFindings []map[string]interface{}
	appLogicFlaws     []map[string]interface{}
	httpProbeResults  []map[string]interface{}
	paramsMatrix      map[string]map[string][]string
	tech              map[string]map[string]bool
	rawURLsSeen       map[string]bool
	// One security-header check per host, not per URL -- these headers are
	// near-universally set site-wide at the server/proxy/CDN layer, so
	// checking every single page would just repeat the identical finding.
	securityHeadersCheckedHosts map[string]bool
	fetchErrors                 map[string]string
	// Set once, first non-empty value wins -- see ResolveDiscoveredURL's
	// doc comment. Real SPAs are near-universally consistent (every route
	// falls back to serving the identical index.html), so a single shared
	// value is the correct model, not per-page tracking.
	discoveredBaseHref string
	// Content-hash dedup: skip the expensive ~979-signature secret scan
	// and logic-flaw scan on a body already scanned once under a
	// different URL (common with server-side SPA fallback routing, and
	// previously exacerbated by base-href mis-resolution producing many
	// bogus duplicate paths for the same JS chunk). Link/endpoint
	// DISCOVERY is never skipped -- only the redundant heuristic
	// scanning -- so this is a pure performance optimization with no risk
	// to crawl completeness.
	contentHashesSeen map[[32]byte]bool

	startTime       time.Time
	frontier        *Frontier
	pendingFrontier []string
	lastSavedFiles  map[string]string
}

type NativeCrawlerOpts struct {
	TargetURL         string
	OutputDir         string
	MaxURLs           *int
	Concurrency       int
	RateLimit         float64 // 0 = unlimited
	Proxy             string
	TimeoutSec        int
	Passive           bool
	ParamsDiscovery   bool
	Resume            bool
	MaxRuntimeMinutes *float64
	IncludeSubdomains bool
	ExtraDomains      []string
	ExcludePatterns   []string
	StatusInterval    float64
	RenderJS          bool
	ChromePath        string
	RenderConcurrency int
	RenderTimeoutSec  int
}

func NewNativeCrawler(opts NativeCrawlerOpts) (*NativeCrawler, error) {
	scope, err := NewScopeManager(opts.TargetURL, opts.IncludeSubdomains, opts.ExtraDomains, opts.ExcludePatterns)
	if err != nil {
		return nil, err
	}

	// Two independently-constructed transports, never copied by value --
	// http.Transport embeds a sync.Mutex guarding its connection pool, and
	// copying that (e.g. `t2 := *t1`) duplicates the mutex while sharing
	// nothing of the pool it's meant to protect, which is exactly the kind
	// of subtle concurrency bug `go vet` exists to catch (and did, here).
	newTransport := func() *http.Transport {
		t := &http.Transport{}
		if opts.Proxy != "" {
			if proxyURL, err := url.Parse(opts.Proxy); err == nil {
				t.Proxy = http.ProxyURL(proxyURL)
			}
			t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		return t
	}

	client := &http.Client{
		Timeout:   time.Duration(opts.TimeoutSec) * time.Second,
		Transport: newTransport(),
		// Without this, Go's default redirect policy silently follows a
		// 3xx to ANY host (SSO logins, tracking/affiliate redirects, CDN
		// bounces) with zero scope check -- directly violating this
		// tool's core "never touch out-of-scope domains" guarantee.
		// ErrUseLastResponse stops BEFORE the out-of-scope request is ever
		// issued, returning the 3xx response itself (Location header
		// intact) instead of silently fetching/scanning whatever it
		// points to. In-scope redirect chains (http->https, bare domain
		// -> www, etc.) are unaffected and still follow normally.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !scope.InScope(req.URL.String()) {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	clientNoRedirect := &http.Client{
		Timeout:   time.Duration(opts.TimeoutSec) * time.Second,
		Transport: newTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var rl *RateLimiter
	if opts.RateLimit > 0 {
		rl = NewRateLimiter(opts.RateLimit)
	}

	var maxRuntimeSec *float64
	if opts.MaxRuntimeMinutes != nil {
		v := *opts.MaxRuntimeMinutes * 60
		maxRuntimeSec = &v
	}

	// Nest every run under a per-target subdirectory (derived from the
	// target's exact host, not the scope's root domain) so crawling
	// apple.com and test.apple.com into the same --output base never mixes
	// their results together -- each target gets its own folder, and
	// re-running the same target later naturally lands back in the same
	// place (which --resume depends on).
	outputDir := filepath.Join(opts.OutputDir, sanitizeDirName(hostOf(opts.TargetURL)))

	workDir := filepath.Join(outputDir, ".work")
	os.MkdirAll(workDir, 0o755)
	os.MkdirAll(outputDir, 0o755)

	c := &NativeCrawler{
		targetURL:        opts.TargetURL,
		outputDir:        outputDir,
		maxURLs:          opts.MaxURLs,
		concurrency:      opts.Concurrency,
		rateLimiter:      rl,
		proxy:            opts.Proxy,
		timeout:          time.Duration(opts.TimeoutSec) * time.Second,
		passive:          opts.Passive,
		paramsDiscovery:  opts.ParamsDiscovery,
		resume:           opts.Resume,
		maxRuntimeSec:    maxRuntimeSec,
		statusInterval:   opts.StatusInterval,
		scope:            scope,
		client:           client,
		clientNoRedirect: clientNoRedirect,
		workDir:          workDir,
		statePath:        filepath.Join(workDir, "state.json"),

		visited:                     make(map[string]bool),
		endpoints:                   make(map[string]bool),
		paths:                       make(map[string]bool),
		jsFiles:                     make(map[string]bool),
		paramsMatrix:                make(map[string]map[string][]string),
		tech:                        make(map[string]map[string]bool),
		rawURLsSeen:                 make(map[string]bool),
		securityHeadersCheckedHosts: make(map[string]bool),
		fetchErrors:                 make(map[string]string),
		contentHashesSeen:           make(map[[32]byte]bool),
		startTime:                   time.Now(),
	}

	if c.resume {
		if _, err := os.Stat(c.statePath); err == nil {
			c.loadState()
		}
	}

	if opts.RenderJS {
		browserPath := findBrowserPath(opts.ChromePath)
		renderConcurrency := opts.RenderConcurrency
		if renderConcurrency < 1 {
			renderConcurrency = 3
		}
		renderTimeoutSec := opts.RenderTimeoutSec
		if renderTimeoutSec < 1 {
			renderTimeoutSec = 20
		}
		renderer, err := NewRenderer(browserPath, renderConcurrency, renderTimeoutSec)
		if err != nil {
			// Best-effort: rendering is a purely additive enhancement, so a
			// missing/broken browser degrades to static-HTML-only crawling
			// rather than aborting the whole run.
			logWarn("--render-js requested but headless browser failed to start (falling back to static HTML only): %v", err)
		} else {
			c.renderer = renderer
			logInfo("Headless rendering enabled (concurrency=%d, per-page timeout=%ds)", renderConcurrency, renderTimeoutSec)
		}
	}

	return c, nil
}

// -- state persistence ---------------------------------------------------

type crawlerState struct {
	Target    string   `json:"target"`
	Visited   []string `json:"visited"`
	Endpoints []string `json:"endpoints"`
	Paths     []string `json:"paths"`
	JSFiles   []string `json:"js_files"`
	Frontier  []string `json:"frontier"`
	Timestamp string   `json:"timestamp"`
}

func (c *NativeCrawler) loadState() {
	data, err := os.ReadFile(c.statePath)
	if err != nil {
		logWarn("Could not load resume state: %v", err)
		return
	}
	var state crawlerState
	if err := json.Unmarshal(data, &state); err != nil {
		logWarn("Could not load resume state: %v", err)
		return
	}
	for _, u := range state.Visited {
		c.visited[u] = true
	}
	for _, u := range state.Endpoints {
		c.endpoints[u] = true
	}
	for _, p := range state.Paths {
		c.paths[p] = true
	}
	for _, j := range state.JSFiles {
		c.jsFiles[j] = true
	}
	c.pendingFrontier = state.Frontier
	logInfo("Resumed state: %d visited, %d endpoints, %d still queued",
		len(c.visited), len(c.endpoints), len(c.pendingFrontier))
}

func (c *NativeCrawler) saveState() {
	c.stateMu.Lock()
	state := crawlerState{
		Target:    c.targetURL,
		Visited:   keysOf(c.visited),
		Endpoints: keysOf(c.endpoints),
		Paths:     keysOf(c.paths),
		JSFiles:   keysOf(c.jsFiles),
		Timestamp: time.Now().Format(time.RFC3339),
	}
	c.stateMu.Unlock()
	if c.frontier != nil {
		state.Frontier = c.frontier.Snapshot()
	}
	data, err := json.Marshal(state)
	if err != nil {
		return
	}
	os.WriteFile(c.statePath, data, 0o644)
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// -- preflight -------------------------------------------------------

func (c *NativeCrawler) preflight() {
	if c.proxy != "" {
		checkProxyReachable(c.proxy)
	}
}

// -- native passive discovery ------------------------------------------

func (c *NativeCrawler) runPassive() map[string]bool {
	found := WaybackDiscovery(c.scope, 30, 100000)
	logInfo("Passive discovery: %d in-scope URLs from Wayback Machine CDX", len(found))

	robotsSitemap := RobotsAndSitemapDiscovery(c.targetURL, c.scope, c.timeoutSecInt())
	logInfo("Passive discovery: %d in-scope URLs from robots.txt Disallow/Allow + sitemap.xml", len(robotsSitemap))
	for u := range robotsSitemap {
		found[u] = true
	}

	return found
}

func (c *NativeCrawler) timeoutSecInt() int {
	return int(c.timeout.Seconds())
}

// -- core fetch/parse/scan/enqueue worker -------------------------------

func (c *NativeCrawler) recordSecretAndLogicFindings(body, sourceURL string, isVendor bool) {
	if isVendor {
		return // still crawled/link-extracted; just skipped for noisy heuristics
	}
	findings := ScanSecrets(body, 25)
	if len(findings) > 0 {
		c.stateMu.Lock()
		for kind, matches := range findings {
			for _, m := range matches {
				c.sensitiveFindings = append(c.sensitiveFindings, map[string]interface{}{
					"url": sourceURL, "source": "static-regex-entropy",
					"type": kind, "value": m.Value(), "severity": "unknown",
				})
			}
		}
		c.stateMu.Unlock()
	}

	flaws := ScanLogicFlaws(body, sourceURL)
	if len(flaws) > 0 {
		c.stateMu.Lock()
		for _, f := range flaws {
			c.appLogicFlaws = append(c.appLogicFlaws, map[string]interface{}{
				"type": f.Type, "severity": f.Severity, "note": f.Note,
				"snippet": f.Snippet, "source": f.Source,
			})
		}
		c.stateMu.Unlock()
	}
}

func (c *NativeCrawler) detectTech(rawURL string, headers http.Header) {
	server := headers.Get("Server")
	poweredBy := headers.Get("X-Powered-By")
	setCookie := strings.ToLower(headers.Get("Set-Cookie"))

	var signals []string
	if server != "" {
		signals = append(signals, strings.SplitN(server, "/", 2)[0])
	}
	if poweredBy != "" {
		signals = append(signals, poweredBy)
	}
	cookieChecks := []struct{ name, tech string }{
		{"phpsessid", "PHP"}, {"jsessionid", "Java"}, {"asp.net_sessionid", "ASP.NET"},
		{"laravel_session", "Laravel"}, {"_csrf", "CSRF-protected framework"},
	}
	for _, cc := range cookieChecks {
		if strings.Contains(setCookie, cc.name) {
			signals = append(signals, cc.tech)
		}
	}

	signals = append(signals, detectURLBasedTech(rawURL)...)

	if len(signals) == 0 {
		return
	}
	host := hostOf(rawURL)
	c.stateMu.Lock()
	if c.tech[host] == nil {
		c.tech[host] = make(map[string]bool)
	}
	for _, s := range signals {
		c.tech[host][s] = true
	}
	c.stateMu.Unlock()
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Host
}

var dirNameUnsafeReplacer = strings.NewReplacer(
	":", "_", "/", "_", "\\", "_", "*", "_", "?", "_", `"`, "_", "<", "_", ">", "_", "|", "_",
)

// sanitizeDirName makes a URL host (possibly carrying a non-default port,
// e.g. "test.apple.com:8443") safe to use as a filesystem directory name on
// both Windows and Linux.
func sanitizeDirName(host string) string {
	if host == "" {
		return "unknown-target"
	}
	return dirNameUnsafeReplacer.Replace(host)
}

func urlPathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Path
}

// fetchAndProcess runs in a worker goroutine: fetch one URL, parse it for
// links/forms/inline scripts, regex-extract JS endpoints, scan for
// secrets/logic flaws, and push newly-discovered in-scope URLs onto the
// frontier. Direct port of _fetch_and_process.
func (c *NativeCrawler) fetchAndProcess(rawURL string) {
	if c.rateLimiter != nil {
		c.rateLimiter.Acquire()
	}

	resp, err := fetchWithRetry(c.client, rawURL, "Mozilla/5.0 (compatible; DeepCrawler/3.0)", maxFetchRetries)
	if err != nil {
		c.stateMu.Lock()
		c.fetchErrors[rawURL] = err.Error()
		c.visited[rawURL] = true
		c.stateMu.Unlock()
		return
	}
	defer resp.Body.Close()

	finalURL := rawURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	// Surface a redirect the CheckRedirect policy blocked (see client
	// construction) -- otherwise it silently vanishes with no trace in the
	// output, which would look like the target just returned a 3xx and
	// nothing more, rather than "there was an out-of-scope pivot point
	// here worth knowing about."
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			target := resolveRef(finalURL, loc)
			if !c.scope.InScope(target) {
				logWarn("Blocked out-of-scope redirect: %s -> %s (not followed)", finalURL, target)
				c.stateMu.Lock()
				c.appLogicFlaws = append(c.appLogicFlaws, map[string]interface{}{
					"type": "out_of_scope_redirect", "severity": "info",
					"note":      "Target redirects out of scope -- not followed, per scope-enforcement policy.",
					"snippet":   target,
					"source":    finalURL,
					"locations": []string{finalURL},
				})
				c.stateMu.Unlock()
			}
		}
	}

	contentType := resp.Header.Get("Content-Type")
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 20*1024*1024))
	body := ""
	if err == nil {
		body = string(bodyBytes)
	}

	isDuplicateContent := false
	if body != "" {
		hash := sha256.Sum256([]byte(body))
		c.stateMu.Lock()
		if c.contentHashesSeen[hash] {
			isDuplicateContent = true
		} else {
			c.contentHashesSeen[hash] = true
		}
		c.stateMu.Unlock()
	}

	c.stateMu.Lock()
	c.visited[rawURL] = true
	c.visited[finalURL] = true
	c.endpoints[rawURL] = true
	if pp := urlPathOf(rawURL); pp != "" && pp != "/" {
		c.paths[pp] = true
	}
	c.httpProbeResults = append(c.httpProbeResults, map[string]interface{}{
		"url": rawURL, "method": "GET", "status_code": resp.StatusCode,
		"content_length": len(bodyBytes), "final_url": finalURL,
	})
	c.stateMu.Unlock()

	c.detectTech(rawURL, resp.Header)

	host := hostOf(rawURL)
	c.stateMu.Lock()
	alreadyCheckedHeaders := c.securityHeadersCheckedHosts[host]
	if !alreadyCheckedHeaders {
		c.securityHeadersCheckedHosts[host] = true
	}
	c.stateMu.Unlock()
	if !alreadyCheckedHeaders {
		isHTTPS := strings.HasPrefix(strings.ToLower(rawURL), "https://")
		for _, f := range checkSecurityHeaders(isHTTPS, resp.Header) {
			c.stateMu.Lock()
			c.appLogicFlaws = append(c.appLogicFlaws, map[string]interface{}{
				"type": f.Type, "severity": f.Severity, "note": f.Note,
				"snippet": host, "source": rawURL,
			})
			c.stateMu.Unlock()
		}
	}

	if f := checkCORSReflection(rawURL, resp.Header); f != nil {
		c.stateMu.Lock()
		c.appLogicFlaws = append(c.appLogicFlaws, f)
		c.stateMu.Unlock()
	}

	cleanPath := strings.SplitN(rawURL, "?", 2)[0]
	lowerCT := strings.ToLower(contentType)
	isJS := strings.HasSuffix(cleanPath, ".js") || strings.Contains(lowerCT, "javascript")
	lowerBodyHead := strings.ToLower(firstN(body, 1000))
	isHTML := strings.Contains(lowerCT, "html") || (contentType == "" && strings.Contains(lowerBodyHead, "<html"))

	if isJS {
		c.stateMu.Lock()
		c.jsFiles[rawURL] = true
		c.stateMu.Unlock()
	}

	discovered := make(map[string]bool)
	isVendor := isLikelyVendorFile(rawURL)

	if isHTML {
		result := ExtractLinks(body)
		for l := range result.Links {
			discovered[l] = true
		}
		if result.BaseHref != "" {
			c.stateMu.Lock()
			if c.discoveredBaseHref == "" {
				// base_href itself can (rarely) be relative -- resolve it
				// against the current page's own URL first, per spec.
				c.discoveredBaseHref = resolveRef(rawURL, result.BaseHref)
				logInfo("Discovered <base href> -- using %s as the resolution "+
					"base for relative references site-wide", c.discoveredBaseHref)
			}
			c.stateMu.Unlock()
		}
		if len(result.Forms) > 0 {
			c.stateMu.Lock()
			for _, f := range result.Forms {
				c.forms = append(c.forms, map[string]interface{}{
					"source": rawURL,
					"form": map[string]interface{}{
						"action": f.Action, "method": f.Method, "inputs": f.Inputs,
					},
				})
			}
			c.stateMu.Unlock()
		}
		for _, script := range result.InlineScripts {
			for u := range ExtractURLsFromJS(script) {
				discovered[u] = true
			}
			if !isDuplicateContent {
				c.recordSecretAndLogicFindings(script, rawURL, isVendor)
			}
		}
		for _, comment := range result.Comments {
			for u := range ExtractURLsFromJS(comment) {
				discovered[u] = true
			}
			if !isDuplicateContent {
				c.recordSecretAndLogicFindings(comment, rawURL, isVendor)
			}
		}
	} else if strings.HasSuffix(cleanPath, ".map") {
		// A source map response, fetched because some JS file referenced it
		// (see the isJS branch below). Recover every original source file's
		// full text from sourcesContent -- unminified, real names, real
		// comments -- and treat each one as additional content worth the
		// full secret/logic-flaw/URL-extraction treatment, attributed back
		// to a synthetic per-original-file URL so findings are traceable
		// to exactly which recovered source they came from. Also record
		// the exposure itself: a publicly-reachable source map with
		// embedded original source is a real information-disclosure
		// finding on its own, independent of whatever it reveals.
		if recovered, err := ParseSourceMap(bodyBytes); err == nil && len(recovered) > 0 {
			c.stateMu.Lock()
			c.appLogicFlaws = append(c.appLogicFlaws, map[string]interface{}{
				"type": "exposed_source_map", "severity": "medium",
				"note": fmt.Sprintf("Source map publicly exposed with %d original source file(s) recovered -- "+
					"unminified source often reveals internal endpoints, comments, and logic not visible in the "+
					"shipped bundle.", len(recovered)),
				"snippet": rawURL, "source": rawURL,
			})
			c.stateMu.Unlock()
			for name, srcText := range recovered {
				synthURL := rawURL + "#" + name
				if !isDuplicateContent {
					c.recordSecretAndLogicFindings(srcText, synthURL, false)
				}
				for u := range ExtractURLsFromJS(srcText) {
					discovered[u] = true
				}
			}
		}
	} else {
		// JS file, JSON API response, or unknown-type text -- still worth
		// regex-scanning for embedded endpoints. (In the Python original
		// this branch's condition is `is_js or 'json' in content_type or
		// not is_html` -- since we're only ever in this else when is_html
		// is already false, `not is_html` is always true here, so the
		// branch always runs; preserved verbatim rather than simplified
		// away, matching the original's actual behavior exactly.)
		for u := range ExtractURLsFromJS(body) {
			discovered[u] = true
		}
		if isJS {
			if mapRef := ExtractSourceMappingURL(body); mapRef != "" {
				discovered[mapRef] = true
			}
		}
	}

	if !isDuplicateContent {
		c.recordSecretAndLogicFindings(body, rawURL, isVendor)
	}

	// Headless-rendering pass (--render-js, opt-in): re-fetches this same
	// page through a real browser to catch what a raw HTTP GET structurally
	// cannot -- links/forms/API calls that only exist after client-side JS
	// runs (SPA client-side routing, framework-rendered nav, runtime data
	// fetches). Restricted to HTML responses -- rendering a JS/JSON/binary
	// response in a browser has nothing extra to offer over what the static
	// analysis above already extracted from it.
	if isHTML && c.renderer != nil {
		renderedHTML, networkURLs, err := c.renderer.Render(rawURL)
		if err != nil {
			logWarn("Headless render failed for %s (continuing with static HTML only): %v", rawURL, err)
		} else {
			result := ExtractLinks(renderedHTML)
			for l := range result.Links {
				discovered[l] = true
			}
			for _, u := range networkURLs {
				discovered[u] = true
			}
			renderedHash := sha256.Sum256([]byte(renderedHTML))
			c.stateMu.Lock()
			alreadyScanned := c.contentHashesSeen[renderedHash]
			if !alreadyScanned {
				c.contentHashesSeen[renderedHash] = true
			}
			c.stateMu.Unlock()
			if !alreadyScanned {
				// Attributed to a synthetic #rendered URL, not the plain
				// rawURL, so a secret/flaw found only after JS execution is
				// distinguishable in output from one already visible in the
				// raw server response.
				c.recordSecretAndLogicFindings(renderedHTML, rawURL+"#rendered", isVendor)
			}
		}
	}

	c.stateMu.Lock()
	baseHref := c.discoveredBaseHref
	c.stateMu.Unlock()

	for raw := range discovered {
		full := ResolveDiscoveredURL(c.targetURL, rawURL, raw, baseHref)
		// WebSocket endpoints are real recon findings but not HTTP-fetchable
		// -- record them directly in results rather than queuing them on
		// the HTTP frontier, where they'd only ever produce a harmless but
		// noisy "unsupported protocol scheme" fetch error.
		if strings.HasPrefix(full, "ws://") || strings.HasPrefix(full, "wss://") {
			if c.scope.InScope(full) {
				c.stateMu.Lock()
				c.endpoints[full] = true
				c.stateMu.Unlock()
			}
			continue
		}
		if c.frontier.Add(full) {
			c.stateMu.Lock()
			c.endpoints[full] = true
			c.stateMu.Unlock()
		}
	}
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// -- main frontier crawl loop --------------------------------------------

func (c *NativeCrawler) Crawl() error {
	if c.renderer != nil {
		defer c.renderer.Close()
	}
	c.preflight()
	c.frontier = NewFrontier(c.scope)
	c.frontier.Add(c.targetURL)

	for _, u := range c.pendingFrontier {
		c.frontier.Add(u)
	}
	c.stateMu.Lock()
	for u := range c.endpoints {
		if !c.visited[u] {
			c.frontier.Add(u)
		}
	}
	c.stateMu.Unlock()

	if c.passive {
		for u := range c.runPassive() {
			c.frontier.Add(u)
		}
	}

	status := NewStatusReporter(c, c.statusInterval)
	lastSave := time.Now()

	sem := make(chan struct{}, c.concurrency)
	var wg sync.WaitGroup
	var activeMu sync.Mutex
	active := 0

	interrupted := make(chan os.Signal, 1)
	installInterruptHandler(interrupted)

loop:
	for {
		select {
		case <-interrupted:
			logWarn("Interrupted -- saving partial results collected so far")
			break loop
		default:
		}

		if c.maxRuntimeSec != nil && time.Since(c.startTime).Seconds() >= *c.maxRuntimeSec {
			logWarn("--max-runtime reached, stopping (this is an opt-in cap you set)")
			break
		}
		if c.maxURLs != nil {
			c.stateMu.Lock()
			v := len(c.visited)
			c.stateMu.Unlock()
			if v >= *c.maxURLs {
				logWarn("--max-urls reached, stopping (this is an opt-in cap you set)")
				break
			}
		}

		u, ok := c.frontier.Pop()
		if !ok {
			activeMu.Lock()
			a := active
			activeMu.Unlock()
			if a == 0 {
				logInfo("Frontier genuinely empty -- true fixpoint reached, nothing left to crawl")
				break
			}
			time.Sleep(50 * time.Millisecond)
			status.MaybePrint(c.frontier, false)
			continue
		}

		sem <- struct{}{}
		activeMu.Lock()
		active++
		activeMu.Unlock()
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			defer func() {
				<-sem
				activeMu.Lock()
				active--
				activeMu.Unlock()
			}()
			c.fetchAndProcess(url)
		}(u)

		status.MaybePrint(c.frontier, false)
		if time.Since(lastSave).Seconds() >= 10 {
			c.saveState()
			lastSave = time.Now()
		}
	}

	wg.Wait()
	status.MaybePrint(c.frontier, true)
	status.Finish()
	c.saveState()

	c.runAllMethodsProbe()
	if c.paramsDiscovery {
		c.runParamDiscovery()
	}

	return c.saveResults()
}

// -- native all-HTTP-method probe on protected endpoints -----------------

func (c *NativeCrawler) runAllMethodsProbe() {
	c.stateMu.Lock()
	protectedSet := make(map[string]bool)
	for _, r := range c.httpProbeResults {
		sc, _ := r["status_code"].(int)
		if sc == 401 || sc == 403 {
			if u, ok := r["url"].(string); ok {
				protectedSet[u] = true
			}
		}
	}
	c.stateMu.Unlock()

	if len(protectedSet) == 0 {
		return
	}
	protected := keysOf(protectedSet)
	sort.Strings(protected)
	logInfo("Probing %d protected (401/403) endpoint(s) with every HTTP method", len(protected))

	methods := []string{"HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
	workers := c.concurrency
	if workers > 10 {
		workers = 10
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, target := range protected {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, method := range methods {
				if c.rateLimiter != nil {
					c.rateLimiter.Acquire()
				}
				req, err := http.NewRequest(method, u, nil)
				if err != nil {
					continue
				}
				resp, err := c.clientNoRedirect.Do(req)
				if err != nil {
					continue
				}
				resp.Body.Close()
				if resp.StatusCode >= 400 {
					continue
				}
				var note string
				switch method {
				case "OPTIONS":
					note = "low-confidence: OPTIONS 200 is typical CORS/framework behavior, not usually a real bypass -- verify manually"
				case "HEAD":
					note = "low-confidence: HEAD is often auto-mapped to GET by frameworks -- verify manually"
				default:
					note = "method-bypass-candidate: this verb succeeded where the default method was blocked -- verify manually in Burp before reporting"
				}
				c.stateMu.Lock()
				c.httpProbeResults = append(c.httpProbeResults, map[string]interface{}{
					"url": u, "method": method, "status_code": resp.StatusCode, "note": note,
				})
				c.stateMu.Unlock()
			}
		}(target)
	}
	wg.Wait()
}

// -- native hidden-parameter discovery + vuln-class matrix --------------

func (c *NativeCrawler) runParamDiscovery() {
	c.stateMu.Lock()
	targets := keysOf(c.endpoints)
	c.stateMu.Unlock()
	if len(targets) == 0 {
		return
	}
	sort.Strings(targets)
	logInfo("Running hidden-parameter discovery against %d endpoint(s) with a %d-word built-in list",
		len(targets), len(commonParamWordlist))

	workers := c.concurrency
	if workers > 10 {
		workers = 10
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var resultMu sync.Mutex

	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			baselineResp, err := c.client.Get(u)
			if err != nil {
				return
			}
			baselineBody, _ := io.ReadAll(baselineResp.Body)
			baselineResp.Body.Close()
			baselineStatus := baselineResp.StatusCode
			baselineLen := len(baselineBody)

			found := make(map[string][]string)
			for _, param := range commonParamWordlist {
				if c.rateLimiter != nil {
					c.rateLimiter.Acquire()
				}
				sep := "?"
				if strings.Contains(u, "?") {
					sep = "&"
				}
				testURL := u + sep + param + "=xh_probe_1337"
				resp, err := c.client.Get(testURL)
				if err != nil {
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != baselineStatus || len(body) != baselineLen {
					found[param] = SuggestVulnClasses(param)
				}
			}
			if len(found) > 0 {
				resultMu.Lock()
				c.paramsMatrix[u] = found
				resultMu.Unlock()
			}
		}(target)
	}
	wg.Wait()
}

// -- output --------------------------------------------------------------

func (c *NativeCrawler) saveResults() error {
	timestamp := time.Now().Format("20060102_150405")
	domain := hostOf(c.targetURL)
	files := make(map[string]string)

	writeList := func(name string, items map[string]bool) {
		path := filepath.Join(c.outputDir, fmt.Sprintf("%s_%s.txt", name, timestamp))
		sorted := keysOf(items)
		sort.Strings(sorted)
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("# %s for %s\n# Generated: %s\n", name, domain, time.Now().Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("# Total: %d\n\n", len(sorted)))
		for _, item := range sorted {
			sb.WriteString(item + "\n")
		}
		os.WriteFile(path, []byte(sb.String()), 0o644)
		files[name] = path
	}

	writeJSON := func(name string, data interface{}) {
		path := filepath.Join(c.outputDir, fmt.Sprintf("%s_%s.json", name, timestamp))
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			b = []byte("null")
		}
		os.WriteFile(path, b, 0o644)
		files[name] = path
	}

	c.stateMu.Lock()
	endpointsSnap := copyBoolMap(c.endpoints)
	pathsSnap := copyBoolMap(c.paths)
	jsFilesSnap := copyBoolMap(c.jsFiles)
	rawURLsAll := copyBoolMap(c.rawURLsSeen)
	for u := range c.visited {
		rawURLsAll[u] = true
	}
	sensitiveSnap := append([]map[string]interface{}{}, c.sensitiveFindings...)
	flawsSnap := append([]map[string]interface{}{}, c.appLogicFlaws...)
	probeSnap := append([]map[string]interface{}{}, c.httpProbeResults...)
	formsSnap := append([]map[string]interface{}{}, c.forms...)
	techSnap := make(map[string][]string)
	for host, set := range c.tech {
		list := keysOf(set)
		sort.Strings(list)
		techSnap[host] = list
	}
	fetchErrorsSnap := make(map[string]string)
	for k, v := range c.fetchErrors {
		fetchErrorsSnap[k] = v
	}
	paramsMatrixSnap := c.paramsMatrix
	visitedCount := len(c.visited)
	c.stateMu.Unlock()

	writeList("endpoints", endpointsSnap)
	writeList("paths", pathsSnap)
	writeList("javascript_files", jsFilesSnap)
	writeList("all_urls_raw", rawURLsAll)

	dedupedFindings := DedupeWithLocations(sensitiveSnap, []string{"type", "value"}, []string{"severity"},
		func(item map[string]interface{}) interface{} {
			u, ok := item["url"]
			if !ok || u == nil || u == "" {
				return nil
			}
			return map[string]interface{}{"url": item["url"], "source": item["source"]}
		})
	writeJSON("sensitive_findings", dedupedEntriesToJSON(dedupedFindings))

	dedupedFlaws := DedupeWithLocations(flawsSnap, []string{"type", "snippet"}, []string{"severity", "note"},
		func(item map[string]interface{}) interface{} {
			return item["source"]
		})
	writeJSON("app_logic_flaws", dedupedEntriesToJSON(dedupedFlaws))

	writeJSON("http_probe", probeSnap)
	writeJSON("params_matrix", paramsMatrixSnap)
	writeJSON("forms", formsSnap)
	writeJSON("technologies", techSnap)
	writeJSON("fetch_errors", fetchErrorsSnap)

	summaryPath := filepath.Join(c.outputDir, fmt.Sprintf("summary_%s.txt", timestamp))
	elapsed := time.Since(c.startTime).Seconds()

	protectedCount := 0
	seenProtected := make(map[string]bool)
	highConf, lowConf := 0, 0
	for _, r := range probeSnap {
		sc, _ := r["status_code"].(int)
		_, hasNote := r["note"]
		if (sc == 401 || sc == 403) && !hasNote {
			if u, ok := r["url"].(string); ok && !seenProtected[u] {
				seenProtected[u] = true
				protectedCount++
			}
		}
		if note, ok := r["note"].(string); ok {
			if strings.HasPrefix(note, "method-bypass-candidate") {
				highConf++
			} else if strings.HasPrefix(note, "low-confidence") {
				lowConf++
			}
		}
	}

	var sb strings.Builder
	sb.WriteString("Deep Crawler - Standalone Native Engine (Go) - Summary Report\n")
	sb.WriteString(strings.Repeat("=", 62) + "\n")
	sb.WriteString(fmt.Sprintf("Target: %s\n", c.targetURL))
	sb.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Elapsed: %.1fs\n\n", elapsed))
	sb.WriteString("Statistics:\n")
	sb.WriteString(fmt.Sprintf("  URLs visited:       %d\n", visitedCount))
	sb.WriteString(fmt.Sprintf("  Endpoints:          %d\n", len(endpointsSnap)))
	sb.WriteString(fmt.Sprintf("  Paths:              %d\n", len(pathsSnap)))
	sb.WriteString(fmt.Sprintf("  JS files:           %d\n", len(jsFilesSnap)))
	sb.WriteString(fmt.Sprintf("  Forms:              %d\n", len(formsSnap)))
	sb.WriteString(fmt.Sprintf("  Fetch errors:       %d\n", len(fetchErrorsSnap)))
	sb.WriteString(fmt.Sprintf("  Sensitive findings: %d unique (%d raw occurrences before dedup)\n",
		len(dedupedFindings), len(sensitiveSnap)))
	sb.WriteString(fmt.Sprintf("  Logic flaws:        %d unique (%d raw occurrences before dedup)\n",
		len(dedupedFlaws), len(flawsSnap)))
	paramCount := 0
	for _, v := range paramsMatrixSnap {
		paramCount += len(v)
	}
	sb.WriteString(fmt.Sprintf("  Params discovered:  %d\n", paramCount))
	sb.WriteString(fmt.Sprintf("  Endpoints probed:   %d of %d discovered\n", visitedCount, len(endpointsSnap)))
	sb.WriteString(fmt.Sprintf("  401/403 found:      %d -- each retried across every HTTP method (see http_probe_*.json)\n", protectedCount))
	sb.WriteString(fmt.Sprintf("  Method-bypass hits: %d (+%d low-confidence OPTIONS/HEAD, verify manually)\n", highConf, lowConf))

	os.WriteFile(summaryPath, []byte(sb.String()), 0o644)
	files["summary"] = summaryPath

	logInfo("Results saved to %s", c.outputDir)
	c.lastSavedFiles = files
	return nil
}

func copyBoolMap(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func dedupedEntriesToJSON(entries []DedupedEntry) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(entries))
	for _, e := range entries {
		m := make(map[string]interface{})
		for k, v := range e.Fields {
			m[k] = v
		}
		m["locations"] = e.Locations
		m["seen_count"] = e.SeenCount
		out = append(out, m)
	}
	return out
}

func checkProxyReachable(proxy string) {
	u, err := url.Parse(proxy)
	if err != nil {
		logWarn("Could not parse proxy '%s' for reachability check", proxy)
		return
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "80"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
	if err != nil {
		logWarn("Proxy %s:%s is NOT reachable from here. Note: in this environment "+
			"WSL has previously been confirmed unable to reach Windows-side "+
			"127.0.0.1 (e.g. Burp) directly. If you need Burp visibility, use "+
			"the standard workflow instead: let this tool find candidates, then "+
			"manually reconstruct the interesting requests in Burp Repeater.", host, port)
		return
	}
	conn.Close()
	logInfo("Proxy %s:%s is reachable from this shell.", host, port)
}
