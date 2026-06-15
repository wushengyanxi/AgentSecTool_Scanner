package openclaw

import (
	"context"
	"math"
	"net"
	"time"
)

// Options 配置一次探测。
type Options struct {
	TLS          bool
	Timeout      time.Duration
	Dial         dialFunc       // nil → 默认 net.Dialer
	Fingerprints *FingerprintDB // nil → 仅直读版本
}

// Probe 对单个目标做只读探测，返回判定与版本。这是与框架无关的入口，
// ZGrab2 模块与任何 runner 都封装它。
func Probe(ctx context.Context, host string, port uint16, opts Options) Result {
	if opts.Timeout <= 0 {
		opts.Timeout = 8 * time.Second
	}
	dial := opts.Dial
	if dial == nil {
		d := &net.Dialer{}
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		}
	}

	var ev Evidence
	probeHTTP(ctx, host, port, opts.TLS, opts.Timeout, &ev)
	probeWS(ctx, host, port, opts.TLS, opts.Timeout, dial, &ev)

	conf, isOC, sigs := score(ev)
	ver, vsrc, vcand := determineVersion(ev, opts.Fingerprints)

	return Result{
		IP:                host,
		Port:              port,
		IsOpenClaw:        isOC,
		Confidence:        round4(conf),
		Signals:           sigs,
		Version:           ver,
		VersionSource:     vsrc,
		VersionCandidates: vcand,
		TLS:               opts.TLS,
		Evidence:          ev,
		TS:                time.Now().UTC().Format(time.RFC3339),
	}
}

func round4(f float64) float64 {
	return math.Round(f*1e4) / 1e4
}
