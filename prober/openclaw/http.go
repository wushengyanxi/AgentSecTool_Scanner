package openclaw

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
)

const maxBodyBytes = 256 * 1024

// respSnippet 限制入库的响应体长度，避免单条记录过大（完整体仍用于提取，仅原文截断）。
const respSnippet = 8 * 1024

var (
	titleRe = regexp.MustCompile(`(?is)<title>([^<]*)</title>`)
	// 生产构建的内容哈希资产名，如 assets/index-DC4lnoz-.js / index-B6U1kUNL.css。
	assetRe = regexp.MustCompile(`assets/(index-[A-Za-z0-9_.\-]+\.(?:js|css))`)
)

// probeHTTP 对目标做一组无鉴权 GET，把观测写进 ev，并为每个测试项记录完整请求/响应原文。全程只读。
func probeHTTP(ctx context.Context, host string, port uint16, tlsOn bool, timeout time.Duration, ev *Evidence) {
	client := newHTTPClient(timeout)
	base := fmt.Sprintf("%s://%s:%d", schemeFor(tlsOn), host, port)

	// /healthz —— T4：精确体 {"ok":true,"status":"live"}
	status, body, hdr := httpGet(ctx, client, base+"/healthz")
	if status == http.StatusOK {
		s := string(body)
		ev.HealthzMatch = strings.Contains(s, `"status":"live"`) && strings.Contains(s, `"ok":true`)
	}
	ev.Probes = append(ev.Probes, probeRec(T4, "GET /healthz", host, port, status, hdr, body, ev.HealthzMatch))

	// 首页 —— T6（title）、T5 的资产名、T7（响应头三件套）共用此响应
	status, body, hdr = httpGet(ctx, client, base+"/")
	if status == http.StatusOK {
		if m := titleRe.FindStringSubmatch(string(body)); m != nil {
			ev.Title = strings.TrimSpace(m[1])
		}
		for _, am := range assetRe.FindAllStringSubmatch(string(body), -1) {
			ev.AssetHashes = appendUnique(ev.AssetHashes, am[1])
		}
		if hasHeaderTriplet(hdr) {
			ev.HeaderTriplet = true
		}
	}
	// 首页这条记录在 matched 里支撑 T6/T7（title 命中或头三件套），hit 取二者之一。
	ev.Probes = append(ev.Probes, probeRec("home", "GET /", host, port, status, hdr, body,
		ev.Title == TitleMarker || ev.HeaderTriplet))

	// control-ui-config —— T1（200+serverVersion）/ T3（401）；CSP、serverVersion
	status, body, hdr = httpGet(ctx, client, base+ControlUIConfigPath)
	if status != 0 {
		ev.ControlUIStatus = status
		if csp := hdr.Get("Content-Security-Policy"); csp != "" {
			ev.CSP = csp
			ev.CSPSHA256 = sha256hex(csp)
		}
		if status == http.StatusOK {
			var cfg struct {
				ServerVersion string `json:"serverVersion"`
			}
			if json.Unmarshal(body, &cfg) == nil {
				ev.ServerVersion = cfg.ServerVersion
			}
		}
		if !ev.HeaderTriplet && hasHeaderTriplet(hdr) {
			ev.HeaderTriplet = true
		}
	}
	t1or3 := (status == http.StatusOK && ev.ServerVersion != "") || status == http.StatusUnauthorized
	ev.Probes = append(ev.Probes, probeRec("control-ui", "GET "+ControlUIConfigPath, host, port, status, hdr, body, t1or3))

	// favicon —— T5：md5 比对
	status, body, _ = httpGet(ctx, client, base+"/favicon.ico")
	if status == http.StatusOK && len(body) > 0 {
		ev.FaviconMD5 = fmt.Sprintf("%x", md5.Sum(body))
	}
	ev.Probes = append(ev.Probes, probeRec(T5, "GET /favicon.ico", host, port, status, nil, body, ev.FaviconMD5 == FaviconMD5))
}

// probeRec 把一次 HTTP 请求/响应组装成 ProbeRecord（响应体截断至 respSnippet，避免记录过大）。
func probeRec(id, reqLine, host string, port uint16, status int, hdr http.Header, body []byte, hit bool) ProbeRecord {
	req := fmt.Sprintf("%s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: %s\r\n", reqLine, host, port, scannerUserAgent)
	var resp strings.Builder
	if status == 0 {
		resp.WriteString("(无响应 / 连接失败)")
	} else {
		fmt.Fprintf(&resp, "HTTP/1.1 %d\r\n", status)
		for k, vs := range hdr {
			for _, v := range vs {
				fmt.Fprintf(&resp, "%s: %s\r\n", k, v)
			}
		}
		resp.WriteString("\r\n")
		b := body
		if len(b) > respSnippet {
			b = b[:respSnippet]
		}
		resp.Write(b)
		if len(body) > respSnippet {
			fmt.Fprintf(&resp, "\n…(响应体截断，原长 %d 字节)", len(body))
		}
	}
	return ProbeRecord{ID: id, Request: req, Response: resp.String(), Hit: hit}
}

// sharedTransport 是全进程共用的一个 Transport。http.Transport 自带并发安全的连接池，
// 多 goroutine 共享一个即可——这正是它被设计的用法。每台目标各 new 一个 Transport 会
// 让用完的空闲连接（keep-alive）变成无人回收的孤儿 fd，高并发下累积撞穿 ulimit；共享一个
// 池子则受 MaxIdleConns / IdleConnTimeout 约束，空闲连接有上限、会自动超时回收。
var sharedTransport = &http.Transport{
	TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	DisableKeepAlives:   false,
	ForceAttemptHTTP2:   false,
	MaxIdleConns:        256,             // 全局空闲连接上限
	MaxIdleConnsPerHost: 4,              // 单台目标本就只发几个 GET，无需更多
	IdleConnTimeout:     5 * time.Second, // 空闲连接超时自动关，不靠 GC、不靠对端
}

// newHTTPClient 复用全进程共享的 Transport，只把每台不同的总超时绑到轻量的 Client 上。
func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: sharedTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func schemeFor(tlsOn bool) string {
	if tlsOn {
		return "https"
	}
	return "http"
}

// httpGet 返回 (status, body, header)；网络错误时 status=0。只读 GET。
func httpGet(ctx context.Context, client *http.Client, url string) (int, []byte, http.Header) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, nil
	}
	req.Header.Set("User-Agent", scannerUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return resp.StatusCode, body, resp.Header
}

func hasHeaderTriplet(h http.Header) bool {
	if h == nil {
		return false
	}
	xcto := strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff")
	ref := strings.EqualFold(strings.TrimSpace(h.Get("Referrer-Policy")), "no-referrer")
	pp := strings.Contains(h.Get("Permissions-Policy"), "microphone=(self)")
	return xcto && ref && pp
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)
}

func appendUnique(xs []string, x string) []string {
	if slices.Contains(xs, x) {
		return xs
	}
	return append(xs, x)
}
