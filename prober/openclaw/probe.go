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

	// 可达性门槛：先做一次 TCP 连接探端口。连不上的目标（被墙/黑洞/端口关）占公网扫描的
	// 绝大多数，对它们直接返回失败原因，不再发 HTTP/WS——否则每个不可达目标都要白白耗掉
	// 4 个 HTTP GET + WS 各自的超时（串行累加可达数十秒），把 worker 长期钉死、有效并发塌方。
	if reach, ok := dialReachable(ctx, dial, host, port, opts.Timeout); !ok {
		return Result{
			IP: host, Port: port, TLS: opts.TLS, ErrorType: reach,
			TS: time.Now().UTC().Format(time.RFC3339),
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
	// 端口可达但探不出 OpenClaw（连得上、非目标服务）：标 down，供默认终端输出。
	if !verdict && len(matched) == 0 && ev.ControlUIStatus == 0 {
		res.ErrorType = ErrDown
	}
	return res
}

// dialReachable 做一次 TCP 连接探端口，作为 HTTP/WS 探测前的可达性门槛。
// 返回 (失败原因, 是否可达)：可达时第二个返回值为 true（连接已关闭，原因为空）；
// 不可达时为 false，并按错误区分 timeout/refused/unreachable/down 供报告。
func dialReachable(ctx context.Context, dial dialFunc, host string, port uint16, timeout time.Duration) (string, bool) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dial(cctx, "tcp", net.JoinHostPort(host, itoa(port)))
	if err == nil {
		_ = conn.Close()
		return "", true // 端口开着，放行去做 HTTP/WS 探测
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return ErrTimeout, false
	case strings.Contains(err.Error(), "refused"):
		return ErrRefused, false
	case strings.Contains(err.Error(), "no route") || strings.Contains(err.Error(), "unreachable"):
		return ErrUnreach, false
	default:
		return ErrDown, false
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
