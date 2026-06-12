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

var (
	titleRe = regexp.MustCompile(`(?is)<title>([^<]*)</title>`)
	// 生产构建的内容哈希资产名，如 assets/index-DC4lnoz-.js / index-B6U1kUNL.css。
	assetRe = regexp.MustCompile(`assets/(index-[A-Za-z0-9_.\-]+\.(?:js|css))`)
)

// probeHTTP 对目标做一组无鉴权 GET，把观测写进 ev。全程只读。
func probeHTTP(ctx context.Context, host string, port uint16, tlsOn bool, timeout time.Duration, ev *Evidence) {
	client := newHTTPClient(timeout)
	base := fmt.Sprintf("%s://%s:%d", schemeFor(tlsOn), host, port)

	// /healthz —— 精确体 {"ok":true,"status":"live"}
	if status, body, _ := httpGet(ctx, client, base+"/healthz"); status == http.StatusOK {
		s := string(body)
		ev.HealthzMatch = strings.Contains(s, `"status":"live"`) && strings.Contains(s, `"ok":true`)
	}

	// 首页 —— 标题、资产哈希、响应头三件套
	if status, body, hdr := httpGet(ctx, client, base+"/"); status == http.StatusOK {
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

	// control-ui-config —— 路由知识（401/200）、CSP、serverVersion（仅 auth=none 时 200）
	if status, body, hdr := httpGet(ctx, client, base+ControlUIConfigPath); status != 0 {
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

	// favicon —— md5 比对
	if status, body, _ := httpGet(ctx, client, base+"/favicon.ico"); status == http.StatusOK && len(body) > 0 {
		ev.FaviconMD5 = fmt.Sprintf("%x", md5.Sum(body))
	}
}

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: false,
			ForceAttemptHTTP2: false,
		},
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
