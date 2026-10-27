package main

// Simple shared token-bucket rate limiter.
// Direct port of deep_crawler.py's RateLimiter.

import (
	"sync"
	"time"
)

type RateLimiter struct {
	rate      float64
	mu        sync.Mutex
	last      time.Time
	allowance float64
}

func NewRateLimiter(ratePerSec float64) *RateLimiter {
	return &RateLimiter{rate: ratePerSec, last: time.Now(), allowance: ratePerSec}
}

func (r *RateLimiter) Acquire() {
	if r == nil || r.rate <= 0 {
		return
	}
	r.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(r.last).Seconds()
	r.last = now
	r.allowance += elapsed * r.rate
	if r.allowance > r.rate {
		r.allowance = r.rate
	}
	var sleepFor float64
	if r.allowance < 1.0 {
		sleepFor = (1.0 - r.allowance) / r.rate
	} else {
		r.allowance -= 1.0
	}
	r.mu.Unlock()

	if sleepFor > 0 {
		time.Sleep(time.Duration(sleepFor * float64(time.Second)))
	}
}
