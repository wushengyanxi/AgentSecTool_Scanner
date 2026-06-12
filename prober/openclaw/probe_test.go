package openclaw

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// recordConn 记录写入的字节，用于验证只读不变量。
type recordConn struct {
	net.Conn
	written []byte
}

func (c *recordConn) Write(b []byte) (int, error) {
	c.written = append(c.written, b...)
	return c.Conn.Write(b)
}

// startFakeGateway 在 loopback 上模拟一个会立即下发 connect.challenge 的最小 WS 服务端。
func startFakeGateway(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for { // 读升级请求直到空行
			l, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if l == "\r\n" {
				break
			}
		}
		_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		payload := []byte(`{"type":"event","event":"connect.challenge","payload":{"nonce":"x","ts":1}}`)
		_, _ = c.Write(append([]byte{0x81, byte(len(payload))}, payload...))
		time.Sleep(200 * time.Millisecond) // 给客户端机会（错误地）发帧——本测试断言它不发
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestProbeWS_ReadOnlyAndChallenge(t *testing.T) {
	addr, closeFn := startFakeGateway(t)
	defer closeFn()
	host, portStr, _ := net.SplitHostPort(addr)
	port64, _ := strconv.ParseUint(portStr, 10, 16)

	var rec *recordConn
	dial := func(ctx context.Context, network, a string) (net.Conn, error) {
		c, err := net.Dial(network, a)
		if err != nil {
			return nil, err
		}
		rec = &recordConn{Conn: c}
		return rec, nil
	}

	var ev Evidence
	probeWS(context.Background(), host, uint16(port64), false, 3*time.Second, dial, &ev)

	if !ev.WSChallenge {
		t.Fatalf("expected WSChallenge=true")
	}
	w := string(rec.written)
	if !strings.HasPrefix(w, "GET / HTTP/1.1") {
		t.Fatalf("unexpected first bytes: %q", w)
	}
	// 只读不变量：绝不发送 connect 帧或 config.apply。
	if strings.Contains(w, `"method":"connect"`) || strings.Contains(w, "config.apply") {
		t.Fatalf("read-only invariant violated: %q", w)
	}
	// 更强：写入内容应当只有 HTTP 升级请求，其后无任何字节（即不发任何 WS 帧）。
	if !strings.HasSuffix(w, "\r\n\r\n") {
		t.Fatalf("wrote bytes beyond the HTTP upgrade request (a frame was sent?): %q", w)
	}
}

func TestScore(t *testing.T) {
	cases := []struct {
		name   string
		ev     Evidence
		wantOC bool
	}{
		{"ws alone", Evidence{WSChallenge: true}, true},
		{"favicon alone (1 surface)", Evidence{FaviconMD5: FaviconMD5}, false},
		{"title alone (1 surface)", Evidence{Title: TitleMarker}, false},
		{"favicon+healthz cross-surface", Evidence{FaviconMD5: FaviconMD5, HealthzMatch: true}, true},
		{"favicon+title same surface", Evidence{FaviconMD5: FaviconMD5, Title: TitleMarker}, false},
		{"http cluster", Evidence{FaviconMD5: FaviconMD5, Title: TitleMarker, HealthzMatch: true, ControlUIStatus: 401}, true},
		{"nothing", Evidence{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conf, isOC, _ := score(c.ev)
			if isOC != c.wantOC {
				t.Fatalf("isOpenClaw=%v want %v (confidence=%.4f)", isOC, c.wantOC, conf)
			}
		})
	}
}

func TestDetermineVersionDirect(t *testing.T) {
	v, src := determineVersion(Evidence{ServerVersion: "v2026.5.17"}, nil)
	if v != "2026.5.17" || src != "direct" {
		t.Fatalf("got (%q,%q) want (2026.5.17,direct)", v, src)
	}
	if v, src := determineVersion(Evidence{}, nil); v != "" || src != "" {
		t.Fatalf("expected empty version when nothing available, got (%q,%q)", v, src)
	}
}

// TestProbeIntegration 对本地容器 127.0.0.1:18789 做真实探测；容器未起则跳过。
func TestProbeIntegration(t *testing.T) {
	c, err := net.DialTimeout("tcp", "127.0.0.1:18789", 800*time.Millisecond)
	if err != nil {
		t.Skip("no OpenClaw target on 127.0.0.1:18789; skipping integration test")
	}
	_ = c.Close()

	r := Probe(context.Background(), "127.0.0.1", 18789, Options{Timeout: 6 * time.Second})
	if !r.IsOpenClaw {
		t.Fatalf("expected IsOpenClaw=true, got %+v", r)
	}
	if !r.Evidence.WSChallenge {
		t.Errorf("expected WS connect.challenge to be observed")
	}
	t.Logf("integration result: confidence=%.4f signals=%v version=%q source=%q",
		r.Confidence, r.Signals, r.Version, r.VersionSource)
}
