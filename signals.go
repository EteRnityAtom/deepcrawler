package main

// SIGINT/SIGTERM handling -- direct port of deep_crawler.py's
// _handle_term + signal.signal(SIGTERM, ...) wiring. `timeout(1)`, process
// managers, and container orchestrators send SIGTERM, not SIGINT; both are
// mapped to the same interrupt channel so the crawl loop's partial-save
// path always runs on either signal, matching the Python original.

import (
	"os"
	"os/signal"
	"syscall"
)

func installInterruptHandler(ch chan os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
}
