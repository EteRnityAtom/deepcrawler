package main

// Opt-in headless-browser rendering (--render-js) -- closes the single
// biggest structural gap in a pure-HTTP crawler: modern SPAs (React,
// Angular, Vue) often ship an almost-empty index.html and build the real
// DOM, links, and API calls entirely at runtime via client-side JS. A
// crawler that only ever fetches raw HTTP bodies never sees any of that.
//
// This uses a single long-lived headless Chromium instance (chromedp),
// shared across the whole crawl, with a small independent concurrency
// cap (renderConcurrency) separate from the main worker pool -- rendering
// a page is orders of magnitude more expensive (memory, CPU, wall time)
// than an HTTP fetch, so letting all 25+ crawl workers render
// simultaneously would exhaust the host. Each render:
//   1. Navigates to the URL in a fresh tab (cheap -- shares the one browser process).
//   2. Captures every network request the page fires while loading/executing
//      (network.requestWillBeSent) -- this is how XHR/fetch calls a bundled
//      SPA framework issues at runtime get discovered, independent of
//      whatever endpoint strings happen to appear as string literals in
//      the JS source.
//   3. Waits briefly for async rendering to settle, then dumps the final
//      DOM as HTML -- run back through the same ExtractLinks used for
//      static HTML, so client-rendered <a>/<script>/<form> elements that
//      never existed in the raw server response get discovered too.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

type Renderer struct {
	allocCtx    context.Context
	allocCancel context.CancelFunc
	browserCtx  context.Context
	sem         chan struct{}
	timeout     time.Duration
}

// findBrowserPath looks for a usable Chromium/Chrome/Edge binary across the
// handful of places it's likely to actually be, without requiring the user
// to install anything new on top of what pentest environments already have
// (Playwright's cached Chromium in WSL, or a system browser on Windows).
// Returns "" if nothing is found, in which case chromedp's own built-in
// PATH-based detection gets one more shot before rendering is disabled.
func findBrowserPath(override string) string {
	if override != "" {
		return override
	}
	if env := os.Getenv("DEEPCRAWLER_CHROME_PATH"); env != "" {
		return env
	}

	var candidates []string
	if runtime.GOOS == "windows" {
		candidates = []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		}
	} else {
		candidates = []string{
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
		}
		// Playwright's cached Chromium (already present in the WSL pentest
		// toolkit) -- version-numbered directory, so glob for it.
		if home, err := os.UserHomeDir(); err == nil {
			matches, _ := filepath.Glob(filepath.Join(home, ".cache", "ms-playwright", "chromium-*", "chrome-linux64", "chrome"))
			candidates = append(candidates, matches...)
		}
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c
		}
	}
	return ""
}

// NewRenderer starts one headless Chromium instance and keeps it running
// for the whole crawl. browserPath == "" lets chromedp fall back to its own
// PATH-based auto-detection. renderConcurrency caps how many tabs can be
// rendering at once, independent of the main HTTP worker pool.
func NewRenderer(browserPath string, renderConcurrency int, timeoutSec int) (*Renderer, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		// Running as root (the norm in this WSL pentest environment) --
		// Chromium's sandbox refuses to start as root without this.
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	if browserPath != "" {
		opts = append(opts, chromedp.ExecPath(browserPath))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	browserCtx, _ := chromedp.NewContext(allocCtx)
	// Force the browser process to actually launch now (rather than lazily
	// on first navigation) so a missing/broken binary fails fast, here,
	// with a clear error -- not confusingly mid-crawl on the first render.
	if err := chromedp.Run(browserCtx); err != nil {
		allocCancel()
		return nil, err
	}

	if renderConcurrency < 1 {
		renderConcurrency = 1
	}
	return &Renderer{
		allocCtx:    allocCtx,
		allocCancel: allocCancel,
		browserCtx:  browserCtx,
		sem:         make(chan struct{}, renderConcurrency),
		timeout:     time.Duration(timeoutSec) * time.Second,
	}, nil
}

func (r *Renderer) Close() {
	r.allocCancel()
}

// Render navigates to targetURL in a fresh tab under the shared browser,
// waits for the page to settle, and returns the fully-rendered DOM plus
// every URL the page requested over the network while doing so. A render
// failure (timeout, JS error, navigation error) is non-fatal to the crawl
// -- the caller already has whatever the plain HTTP fetch found; rendering
// is purely additive.
func (r *Renderer) Render(targetURL string) (renderedHTML string, networkURLs []string, err error) {
	r.sem <- struct{}{}
	defer func() { <-r.sem }()

	tabCtx, tabCancel := chromedp.NewContext(r.browserCtx)
	defer tabCancel()
	tabCtx, timeoutCancel := context.WithTimeout(tabCtx, r.timeout)
	defer timeoutCancel()

	var mu sync.Mutex
	seen := make(map[string]bool)
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		if e, ok := ev.(*network.EventRequestWillBeSent); ok {
			url := e.Request.URL
			if url == "" || strings.HasPrefix(url, "data:") {
				return
			}
			mu.Lock()
			seen[url] = true
			mu.Unlock()
		}
	})

	err = chromedp.Run(tabCtx,
		network.Enable(),
		chromedp.Navigate(targetURL),
		// Give async rendering (data fetches, lazy components, client-side
		// routing) a moment to settle. A fixed short sleep rather than a
		// full network-idle wait -- keeps render cost bounded and
		// predictable across a large crawl instead of hanging on a page
		// with a long-poll or websocket connection open.
		chromedp.Sleep(1500*time.Millisecond),
		chromedp.OuterHTML("html", &renderedHTML, chromedp.ByQuery),
	)

	mu.Lock()
	for u := range seen {
		networkURLs = append(networkURLs, u)
	}
	mu.Unlock()

	return renderedHTML, networkURLs, err
}
