package main

// CLI. Direct port of deep_crawler.py's argparse setup and main().

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	fs := flag.NewFlagSet("deep_crawler", flag.ExitOnError)

	output := fs.String("output", "./crawl_results", "output directory")
	fs.StringVar(output, "o", "./crawl_results", "output directory (shorthand)")
	maxURLs := fs.Int("max-urls", 0, "OPTIONAL cap on total URLs visited (default: unbounded, 0 = unbounded)")
	fs.IntVar(maxURLs, "r", 0, "OPTIONAL cap on total URLs visited (shorthand)")
	concurrency := fs.Int("concurrency", 25, "concurrent worker count")
	fs.IntVar(concurrency, "c", 25, "concurrent worker count (shorthand)")
	rateLimit := fs.Float64("rate-limit", 0, "OPTIONAL max requests/sec across all workers (default: unlimited, 0 = unlimited)")
	timeout := fs.Int("timeout", 10, "per-request timeout in seconds")
	fs.IntVar(timeout, "t", 10, "per-request timeout in seconds (shorthand)")
	maxRuntime := fs.Float64("max-runtime", 0, "OPTIONAL wall-clock cap in minutes (default: unbounded, 0 = unbounded)")
	proxy := fs.String("proxy", "", "e.g. http://127.0.0.1:8080")
	noPassive := fs.Bool("no-passive", false, "skip Wayback Machine historical discovery")
	noParams := fs.Bool("no-params", false, "skip hidden-parameter discovery")
	resume := fs.Bool("resume", false, "resume from previous run state in output dir")
	noSubdomains := fs.Bool("no-subdomains", false, "restrict scope to exact domain only")
	statusInterval := fs.Float64("status-interval", 1.0, "status bar refresh interval in seconds")
	renderJS := fs.Bool("render-js", false, "OPTIONAL: render every HTML page in headless Chromium to catch client-side-JS-only links/forms/API calls (slower; requires a Chrome/Chromium/Edge binary)")
	chromePath := fs.String("chrome-path", "", "path to a Chrome/Chromium/Edge binary (default: auto-detect)")
	renderConcurrency := fs.Int("render-concurrency", 3, "max simultaneous headless-render tabs (independent of --concurrency)")
	renderTimeout := fs.Int("render-timeout", 20, "per-page headless-render timeout in seconds")

	var allowDomain stringSliceFlag
	fs.Var(&allowDomain, "allow-domain", "extra in-scope domain (repeatable)")
	var exclude stringSliceFlag
	fs.Var(&exclude, "exclude", "regex of URLs to exclude (repeatable)")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Deep Crawler - standalone native security reconnaissance crawler (Go port)")
		fmt.Fprintln(os.Stderr, "\nUsage: deep_crawler [flags] <target-url>")
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  deep_crawler https://target.com")
		fmt.Fprintln(os.Stderr, "  deep_crawler https://target.com --proxy http://127.0.0.1:8080")
		fmt.Fprintln(os.Stderr, "  deep_crawler https://target.com --resume")
		fmt.Fprintln(os.Stderr, "  deep_crawler https://target.com --max-urls 2000   (opt-in cap)")
		fmt.Fprintln(os.Stderr, "\nBy default there is NO cap on URLs visited or wall-clock runtime -- the")
		fmt.Fprintln(os.Stderr, "crawl runs to a true fixpoint (frontier genuinely empty). Set --max-urls /")
		fmt.Fprintln(os.Stderr, "--max-runtime yourself only if you deliberately want a bound.")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
	}

	fs.Parse(os.Args[1:])

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: target is required")
		fs.Usage()
		os.Exit(1)
	}
	target := fs.Arg(0)
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}

	exeDir, _ := os.Executable()
	nucleiPath := nucleiSignaturesDefaultPath(filepath.Dir(exeDir))
	if _, err := os.Stat(nucleiPath); err != nil {
		// fall back to the current working directory (e.g. `go run .`)
		if cwd, err2 := os.Getwd(); err2 == nil {
			nucleiPath = nucleiSignaturesDefaultPath(cwd)
		}
	}
	initSecretSignatures(nucleiPath)

	var maxURLsPtr *int
	if *maxURLs > 0 {
		maxURLsPtr = maxURLs
	}
	var maxRuntimePtr *float64
	if *maxRuntime > 0 {
		maxRuntimePtr = maxRuntime
	}

	crawler, err := NewNativeCrawler(NativeCrawlerOpts{
		TargetURL:         target,
		OutputDir:         *output,
		MaxURLs:           maxURLsPtr,
		Concurrency:       *concurrency,
		RateLimit:         *rateLimit,
		Proxy:             *proxy,
		TimeoutSec:        *timeout,
		Passive:           !*noPassive,
		ParamsDiscovery:   !*noParams,
		Resume:            *resume,
		MaxRuntimeMinutes: maxRuntimePtr,
		IncludeSubdomains: !*noSubdomains,
		ExtraDomains:      allowDomain,
		ExcludePatterns:   exclude,
		StatusInterval:    *statusInterval,
		RenderJS:          *renderJS,
		ChromePath:        *chromePath,
		RenderConcurrency: *renderConcurrency,
		RenderTimeoutSec:  *renderTimeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing crawler: %v\n", err)
		os.Exit(1)
	}

	if err := crawler.Crawl(); err != nil {
		fmt.Fprintf(os.Stderr, "Error during crawl: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("CRAWL COMPLETE")
	fmt.Println(strings.Repeat("=", 60))

	keys := make([]string, 0, len(crawler.lastSavedFiles))
	for k := range crawler.lastSavedFiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  [%s] %s\n", k, filepath.Base(crawler.lastSavedFiles[k]))
	}
	fmt.Printf("\nAll files in: %s\n", crawler.outputDir)
}
