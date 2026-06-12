// ocprobe 是 openclaw 探测核心的轻量 CLI runner：读 candidates（IP[,port] 每行），
// 并发探测，输出 JSONL。它与 ZGrab2 模块功能等价，零重依赖，
// 用作本地验证、M2 指纹 harness 的驱动，以及 M3/M4 的串联。
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	oc "github.com/wushengyanxi/agentsectool-scanner/prober/openclaw"
)

func main() {
	in := flag.String("f", "", "目标文件，每行 IP[,port]；缺省读 stdin")
	out := flag.String("o", "", "输出 JSONL 文件；缺省写 stdout")
	defPort := flag.Uint("port", oc.DefaultPort, "默认端口")
	tlsOn := flag.Bool("tls", false, "强制所有目标用 TLS；缺省按端口自动（443/8443/9443 → TLS）")
	timeout := flag.Duration("timeout", 8*time.Second, "单目标超时")
	conc := flag.Int("concurrency", 50, "并发目标数")
	fpPath := flag.String("fingerprints", "", "指纹库 JSON 路径（用于隐式版本反推）")
	flag.Parse()

	scanner := bufio.NewScanner(os.Stdin)
	if *in != "" {
		f, err := os.Open(*in)
		if err != nil {
			fail(err)
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	}
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fail(err)
		}
		defer f.Close()
		w = f
	}

	var fpdb *oc.FingerprintDB
	if *fpPath != "" {
		db, err := oc.LoadFingerprintDB(*fpPath)
		if err != nil {
			fail(err)
		}
		fpdb = db
	}

	type target struct {
		host string
		port uint16
	}
	targets := make(chan target, 1024)
	var wg sync.WaitGroup
	var mu sync.Mutex
	enc := json.NewEncoder(w)

	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range targets {
				ctx, cancel := context.WithTimeout(context.Background(), *timeout+2*time.Second)
				tls := *tlsOn || t.port == 443 || t.port == 8443 || t.port == 9443
				res := oc.Probe(ctx, t.host, t.port, oc.Options{TLS: tls, Timeout: *timeout, Fingerprints: fpdb})
				cancel()
				mu.Lock()
				_ = enc.Encode(res)
				mu.Unlock()
			}
		}()
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host := line
		port := uint16(*defPort)
		if c := strings.IndexByte(line, ','); c >= 0 {
			host = strings.TrimSpace(line[:c])
			if p, err := strconv.ParseUint(strings.TrimSpace(line[c+1:]), 10, 16); err == nil {
				port = uint16(p)
			}
		}
		targets <- target{host, port}
	}
	close(targets)
	wg.Wait()
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ocprobe:", err)
	os.Exit(1)
}
