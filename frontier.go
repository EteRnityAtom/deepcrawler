package main

// Thread-safe frontier (work queue) -- the single scope-enforcement
// chokepoint. Direct port of deep_crawler.py's Frontier class. Add() is the
// ONE place in the whole crawler where a URL can enter the system to be
// fetched -- every discovery path (HTML links, JS-extracted paths, passive
// sources) must funnel through it.

import "sync"

type Frontier struct {
	scope *ScopeManager
	queue []string
	seen  map[string]bool
	mu    sync.Mutex
}

func NewFrontier(scope *ScopeManager) *Frontier {
	return &Frontier{scope: scope, seen: make(map[string]bool)}
}

func (f *Frontier) Add(u string) bool {
	if u == "" {
		return false
	}
	if !f.scope.InScope(u) {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen[u] {
		return false
	}
	f.seen[u] = true
	f.queue = append(f.queue, u)
	return true
}

func (f *Frontier) AddMany(urls map[string]bool) int {
	count := 0
	for u := range urls {
		if f.Add(u) {
			count++
		}
	}
	return count
}

func (f *Frontier) Pop() (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queue) == 0 {
		return "", false
	}
	u := f.queue[0]
	f.queue = f.queue[1:]
	return u, true
}

func (f *Frontier) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queue)
}

// Snapshot returns a copy of the current queue contents (for state
// persistence / --resume), matching Python's list(self.frontier._queue).
func (f *Frontier) Snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.queue))
	copy(out, f.queue)
	return out
}
