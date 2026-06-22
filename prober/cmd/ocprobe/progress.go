package main

// 单行刷新的扫描进度（类似 clawsec pull 的进度行）：不逐个 IP 刷屏，
// 只在一行里持续更新「已扫 / 各分类计数 / 百分比」。
// update 由 worker 在持有全局 mu 的临界区内调用，故内部无需再加锁。

import (
	"fmt"
	"os"
	"time"

	oc "github.com/wushengyanxi/agentsectool-scanner/prober/openclaw"
)

type progressTracker struct {
	total       int       // 目标总数（已知则显示百分比）
	done        int       // 已扫数
	confirmed   int       // 明确 OpenClaw 且取到版本
	confirmedNV int       // 明确 OpenClaw 但版本未知
	suspect     int       // 命中部分特征、未达白名单
	unreachable int       // 探不到（timeout/refused/unreachable/down 合计）
	last        time.Time // 上次刷新时间（节流，避免高频刷屏）
}

func newProgress(total int) *progressTracker {
	return &progressTracker{total: total}
}

// update 累计一条结果，并按节流间隔刷新进度行。
func (p *progressTracker) update(r oc.Result) {
	p.done++
	switch {
	case r.IsOpenClaw && r.Version != "":
		p.confirmed++
	case r.IsOpenClaw:
		p.confirmedNV++
	case r.ErrorType != "":
		p.unreachable++
	default:
		p.suspect++
	}
	// 节流：每 200ms 最多刷一次，外加每扫完一定数量兜底刷新。
	if time.Since(p.last) >= 200*time.Millisecond {
		p.render(false)
		p.last = time.Now()
	}
}

// finish 在全部扫完后刷最后一行并换行。
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
	// \r 回到行首覆盖刷新；输出到 stderr，与 -o 落盘到文件/stdout 互不干扰。
	fmt.Fprintf(os.Stderr,
		"\r已扫 %s%s · 确认(含版本) %d · 确认(版本未知) %d · 疑似 %d · 探不到 %d   ",
		scanned, pct, p.confirmed, p.confirmedNV, p.suspect, p.unreachable)
	_ = final
}
