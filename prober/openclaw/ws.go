package openclaw

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// dialFunc 允许测试注入连接（默认走 net.Dialer）。
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

const maxWSFrameBytes = 1 << 20 // 1 MiB 上限，防止恶意大帧

// probeWS 做一次标准 RFC6455 升级并读首帧；命中 connect.challenge 即记。
//
// 只读不变量：本函数对连接只执行一次 Write —— 那个 HTTP 升级请求。
// 绝不发送任何 WebSocket 数据帧（尤其不发 connect / config.apply）。
func probeWS(ctx context.Context, host string, port uint16, tlsOn bool, timeout time.Duration, dial dialFunc, ev *Evidence) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	if tlsOn {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host})
		_ = tc.SetDeadline(deadline)
		if err := tc.HandshakeContext(ctx); err != nil {
			return
		}
		conn = tc
	}

	// 唯一的一次写：HTTP 升级请求。
	req := "GET / HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: " + scannerUserAgent + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + wsKey() + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return
	}

	br := bufio.NewReader(conn)
	if !readUpgrade101(br) {
		return
	}
	payload, ok := readOneFrame(br)
	if !ok {
		return
	}
	if strings.Contains(string(payload), `"event":"`+WSChallengeEvent+`"`) {
		ev.WSChallenge = true
	}
	// 不发任何帧；defer 直接关闭连接。
}

func wsKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.StdEncoding.EncodeToString(b[:])
}

// readUpgrade101 读状态行并消费响应头，要求状态码 101。
func readUpgrade101(br *bufio.Reader) bool {
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, " 101") {
		return false
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return false
		}
		if l == "\r\n" || l == "\n" {
			return true
		}
	}
}

// readOneFrame 解析一个 RFC6455 帧的载荷（服务端帧通常未掩码，但两种都处理）。
func readOneFrame(br *bufio.Reader) ([]byte, bool) {
	if _, err := br.ReadByte(); err != nil { // FIN/RSV/opcode，接受文本帧
		return nil, false
	}
	h1, err := br.ReadByte()
	if err != nil {
		return nil, false
	}
	masked := h1&0x80 != 0
	ln := int(h1 & 0x7f)
	switch ln {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return nil, false
		}
		ln = int(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return nil, false
		}
		ln = int(binary.BigEndian.Uint64(b[:]))
	}
	if ln < 0 || ln > maxWSFrameBytes {
		return nil, false
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(br, mask[:]); err != nil {
			return nil, false
		}
	}
	payload := make([]byte, ln)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, false
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return payload, true
}
