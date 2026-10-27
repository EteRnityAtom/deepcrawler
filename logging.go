package main

// Minimal logging helper matching Python's
// logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s')
// used throughout deep_crawler.py.

import (
	"fmt"
	"os"
	"time"
)

func timestamp() string {
	return time.Now().Format("2006-01-02 15:04:05,000")
}

func logInfo(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s - INFO - %s\n", timestamp(), fmt.Sprintf(format, args...))
}

func logWarn(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s - WARNING - %s\n", timestamp(), fmt.Sprintf(format, args...))
}

func logDebug(format string, args ...interface{}) {
	// Python's default logging level is INFO, so debug() calls in the
	// original are silent by default -- kept as a no-op here to match,
	// with the call sites preserved for parity/documentation.
	_ = format
	_ = args
}

func isTerminal(f *os.File) bool {
	return termIsTerminal(int(f.Fd()))
}
