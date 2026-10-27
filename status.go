package main

// Live status bar. A live single-line status bar in an interactive
// terminal, or periodic plain log lines when stdout isn't a TTY, so output
// stays clean.
//
// Progress is an ESTIMATE, not exact -- and stated as such. A crawler's
// true "total" work is unknowable until the frontier genuinely drains (you
// discover more of the graph as you go), so the completion fraction here
// is visited/(visited+queued): it can legitimately grow OR shrink as new
// pages/JS files reveal more endpoints than they consume. This is the same
// honest limitation every crawler with a live progress display has (npm
// install, pip, download managers with unknown final size all show the
// same "estimate that moves" behavior) -- the alternative, a bar that
// silently lies about being more precise than it is, would be worse.
import (
	"fmt"
	"os"
	"strings"
	"time"
)

type rateSample struct {
	t       time.Time
	visited int
}

type StatusReporter struct {
	crawler    *NativeCrawler
	interval   time.Duration
	lastPrint  time.Time
	isTTY      bool
	rateWindow []rateSample
	barWidth   int
}

func NewStatusReporter(c *NativeCrawler, intervalSec float64) *StatusReporter {
	return &StatusReporter{
		crawler:  c,
		interval: time.Duration(intervalSec * float64(time.Second)),
		isTTY:    isTerminal(os.Stderr),
		barWidth: 24,
	}
}

func renderProgressBar(fraction float64, width int) string {
	if fraction < 0 {
		fraction = 0
	}
	if fraction > 1 {
		fraction = 1
	}
	filled := int(fraction*float64(width) + 0.5)
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
}

func (s *StatusReporter) MaybePrint(frontier *Frontier, force bool) {
	now := time.Now()
	if !force && now.Sub(s.lastPrint) < s.interval {
		return
	}
	s.lastPrint = now

	c := s.crawler
	c.stateMu.Lock()
	visited := len(c.visited)
	jsFiles := len(c.jsFiles)
	paths := len(c.paths)
	endpoints := len(c.endpoints)
	secrets := len(c.sensitiveFindings)
	flaws := len(c.appLogicFlaws)
	c.stateMu.Unlock()

	queued := frontier.Len()
	knownTotal := visited + queued

	s.rateWindow = append(s.rateWindow, rateSample{t: now, visited: visited})
	if len(s.rateWindow) > 30 {
		s.rateWindow = s.rateWindow[len(s.rateWindow)-30:]
	}

	rate := 0.0
	if len(s.rateWindow) >= 2 {
		t0 := s.rateWindow[0]
		dt := now.Sub(t0.t).Seconds()
		if dt > 0.5 {
			rate = float64(visited-t0.visited) / dt
		}
	}

	var etaStr string
	switch {
	case visited < 3:
		etaStr = "calculating..."
	case rate <= 0.05:
		etaStr = "n/a"
	default:
		etaStr = formatDuration(float64(queued) / rate)
	}
	elapsedStr := formatDuration(now.Sub(c.startTime).Seconds())

	fraction := 0.0
	if knownTotal > 0 {
		fraction = float64(visited) / float64(knownTotal)
	}
	bar := renderProgressBar(fraction, s.barWidth)
	pct := fraction * 100

	rateStr := "-"
	if rate > 0.05 {
		rateStr = fmt.Sprintf("%.1f/s", rate)
	}

	line := fmt.Sprintf(
		"%s %5.1f%% (%d/%d known) | js=%d paths=%d endpoints=%d secrets=%d flaws=%d | rate=%s elapsed=%s eta=%s",
		bar, pct, visited, knownTotal, jsFiles, paths, endpoints, secrets, flaws, rateStr, elapsedStr, etaStr,
	)

	if s.isTTY {
		fmt.Fprint(os.Stderr, "\r"+line+"    ")
	} else {
		logInfo("%s", line)
	}
}

func (s *StatusReporter) Finish() {
	if s.isTTY {
		fmt.Fprintln(os.Stderr)
	}
}

func formatDuration(seconds float64) string {
	secs := int(seconds)
	if secs < 0 {
		secs = 0
	}
	if secs < 60 {
		return fmt.Sprintf("%ds", secs)
	}
	m, s := secs/60, secs%60
	if m < 60 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	h, m2 := m/60, m%60
	return fmt.Sprintf("%dh%dm", h, m2)
}
