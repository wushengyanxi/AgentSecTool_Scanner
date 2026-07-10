package main

import (
	"fmt"
	"os"
	"time"

	"github.com/wushengyanxi/agentsectool-scanner/prober/detectors"
)

type progressTracker struct {
	total       int
	done        int
	confirmed   int
	confirmedNV int
	suspect     int
	unreachable int
	last        time.Time
}

func newProgress(total int) *progressTracker {
	return &progressTracker{total: total}
}

func (p *progressTracker) update(s detectors.Summary) {
	p.done++
	switch {
	case s.ErrorType != "":
		p.unreachable++
	case s.Category == "confirmed" || (s.IsMatch && s.Version != ""):
		p.confirmed++
	case s.Category == "confirmed_no_version" || s.IsMatch:
		p.confirmedNV++
	case s.Category == "suspect" || len(s.Matched) > 0:
		p.suspect++
	}
	if time.Since(p.last) >= 200*time.Millisecond {
		p.render(false)
		p.last = time.Now()
	}
}

func (p *progressTracker) finish() {
	p.render(true)
	fmt.Fprintln(os.Stderr)
}

func (p *progressTracker) render(final bool) {
	pct := ""
	if p.total > 0 {
		pct = fmt.Sprintf(" %5.1f%%", float64(p.done)/float64(p.total)*100)
	}
	scanned := fmt.Sprintf("%d", p.done)
	if p.total > 0 {
		scanned = fmt.Sprintf("%d/%d", p.done, p.total)
	}
	fmt.Fprintf(os.Stderr,
		"\r已扫 %s%s · 确认(含版本) %d · 确认(版本未知) %d · 疑似 %d · 探不到 %d   ",
		scanned, pct, p.confirmed, p.confirmedNV, p.suspect, p.unreachable)
	_ = final
}
