package main

// Retry-with-backoff for transient fetch failures -- without this, a single
// dropped connection or momentary 502/503 from an overloaded target
// permanently loses that page for the rest of the crawl (the frontier
// never revisits a URL once popped). Given the crawl's own explicit "must
// not miss anything" design goal, treating a transient network hiccup the
// same as a genuine 404 was a real gap.

import (
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

const maxFetchRetries = 3

// fetchWithRetry issues a GET request, retrying only failures that are
// plausibly transient: network-level errors (connection reset, timeout,
// DNS blip) and 502/503/504 gateway errors. A genuine 404, 401, 403, or any
// other successful HTTP round-trip is returned immediately, never retried
// -- those are real answers, not glitches. Exponential backoff with jitter
// avoids hammering an already-struggling target or creating a thundering
// herd across the crawler's concurrent workers.
func fetchWithRetry(client *http.Client, url string, userAgent string, maxRetries int) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * 250 * time.Millisecond
			jitter := time.Duration(rand.Int63n(int64(100 * time.Millisecond)))
			time.Sleep(backoff + jitter)
			logDebug("Retrying %s (attempt %d/%d) after: %v", url, attempt, maxRetries, lastErr)
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err // malformed URL -- retrying changes nothing
		}
		req.Header.Set("User-Agent", userAgent)
		// Sending a spoofed, arbitrary Origin on every request costs zero
		// extra round-trips and lets a CORS-reflection misconfiguration
		// (see checkCORSReflection in crawler.go) be caught on the very
		// same request that already needed to happen -- no separate
		// probing pass required. Inert for the overwhelming majority of
		// endpoints that don't branch on Origin at all.
		req.Header.Set("Origin", corsProbeOrigin)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 {
			resp.Body.Close()
			lastErr = fmt.Errorf("transient status %d", resp.StatusCode)
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}
