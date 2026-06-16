package openclaw

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
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

	verdict, matched, rule := evaluate(ev)
	ver, vsrc, vcand := determineVersion(ev, opts.Fingerprints)

	res := Result{
		IP:                host,
		Port:              port,
		IsOpenClaw:        verdict,
		Matched:           matched,
		Rule:              rule,
		Version:           ver,
		VersionSource:     vsrc,
		VersionCandidates: vcand,
		TLS:               opts.TLS,
		Evidence:          ev,
		TS:                time.Now().UTC().Format(time.RFC3339),
	}
	// 探不到任何东西时，分类失败原因（timeout/refused/unreachable/down），供默认终端输出。
	if !verdict && len(matched) == 0 && ev.ControlUIStatus == 0 {
		res.ErrorType = classifyReachability(ctx, dial, host, port, opts.Timeout)
	}
	return res
}

// classifyReachability 在判定不出 OpenClaw 且无任何 HTTP 响应时，做一次 TCP 连接以区分失败原因。
func classifyReachability(ctx context.Context, dial dialFunc, host string, port uint16, timeout time.Duration) string {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dial(cctx, "tcp", net.JoinHostPort(host, itoa(port)))
	if err == nil {
		_ = conn.Close()
		return ErrDown // 端口开着但探不出 OpenClaw —— 非目标服务
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return ErrTimeout
	case strings.Contains(err.Error(), "refused"):
		return ErrRefused
	case strings.Contains(err.Error(), "no route") || strings.Contains(err.Error(), "unreachable"):
		return ErrUnreach
	default:
		return ErrDown
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return errors.Is(err, os.ErrDeadlineExceeded)
}

func itoa(p uint16) string {
	if p == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for p > 0 {
		i--
		b[i] = byte('0' + p%10)
		p /= 10
	}
	return string(b[i:])
}
