// assetprobe is the platform-level scanner runner. It dispatches targets to a
// registered detector by asset type and writes detector-specific JSONL results.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wushengyanxi/agentsectool-scanner/prober/detectors"
	_ "github.com/wushengyanxi/agentsectool-scanner/prober/detectors/openclaw"
	"github.com/wushengyanxi/agentsectool-scanner/prober/targeting"
)

func main() {
	cfg := loadConfig()

	var (
		assetType   = flag.String("type", "openclaw", "资产类型（如 openclaw）")
		portsArg    = flag.String("port", "", "端口，逗号分隔多个（默认取探测器默认端口；config.toml 可覆盖）")
		conc        = flag.Int("concurrency", int(cfg.concurrency), "全局并发探测数")
		timeout     = flag.Duration("timeout", cfg.timeoutPerIP, "单目标探测超时")
		deadline    = flag.Duration("deadline", cfg.deadline, "整个任务的总时长上限（0=不限）")
		rate        = flag.Int("rate", int(cfg.rate), "单个目标 IP 的每秒发包上限（0=不限）")
		logFlag     = flag.Bool("l", cfg.verbose > 0, "详细日志：打印每个目标的完整研判依据（由探测器结果提供）")
		fpPath      = flag.String("fingerprints", "", "指纹库 JSON 路径（探测器可选择使用）")
		outPath     = flag.String("o", "", "JSONL 输出文件；缺省不落盘")
		tlsOn       = flag.Bool("tls", false, "强制所有目标用 TLS（缺省按端口自动）")
		skipUnreach = flag.Bool("skip-unreachable", false, "不落盘探不到的目标（timeout/refused/unreachable/down）")
		progress    = flag.Bool("progress", false, "单行刷新进度（替代逐行输出）")
		listTypes   = flag.Bool("list-types", false, "列出已注册资产类型并退出")
	)
	flagArgs, posArgs := splitArgs(os.Args[1:])
	_ = flag.CommandLine.Parse(flagArgs)

	if *listTypes {
		for _, t := range detectors.Types() {
			fmt.Println(t)
		}
		return
	}

	det, err := detectors.New(*assetType, detectors.Config{FingerprintsPath: *fpPath})
	if err != nil {
		fail(err)
	}

	ports := det.DefaultPorts()
	if len(cfg.ports) > 0 {
		ports = cfg.ports
	}
	if *portsArg != "" {
		ports = parsePorts(*portsArg)
	}
	if len(ports) == 0 {
		fail(fmt.Errorf("未指定端口，且资产类型 %q 无默认端口", *assetType))
	}
	if len(posArgs) == 0 {
		fail(fmt.Errorf("用法：assetprobe --type %s [选项] <目标...>\n  目标可为：精确IP / 文件路径 / - / 通配IP(123.*.*.4) / CIDR(203.0.113.0/24)", *assetType))
	}

	var jsonl *os.File
	if *outPath != "" {
		if dir := filepath.Dir(*outPath); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				fail(err)
			}
		}
		f, err := os.Create(*outPath)
		if err != nil {
			fail(err)
		}
		defer f.Close()
		jsonl = f
	}

	ctx := context.Background()
	if *deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *deadline)
		defer cancel()
	}

	var prog *progressTracker
	if *progress {
		total := 0
		for _, expr := range posArgs {
			_ = targeting.ExpandTarget(expr, func(string) error { total += len(ports); return nil })
		}
		prog = newProgress(total)
	}

	type target struct {
		host string
		port uint16
	}
	targets := make(chan target, 1024)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var enc *json.Encoder
	if jsonl != nil {
		enc = json.NewEncoder(jsonl)
	}
	minInterval := time.Duration(0)
	if *rate > 0 {
		minInterval = time.Second / time.Duration(*rate)
	}

	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range targets {
				if ctx.Err() != nil {
					return
				}
				if minInterval > 0 {
					time.Sleep(minInterval)
				}
				pctx, cancel := context.WithTimeout(ctx, *timeout+2*time.Second)
				useTLS := *tlsOn || t.port == 443 || t.port == 8443 || t.port == 9443
				res, err := det.Probe(pctx, detectors.Target{Host: t.host, Port: t.port, TLS: useTLS}, detectors.ProbeOptions{Timeout: *timeout})
				cancel()

				s := detectors.SummaryOf(res)
				if err != nil && s.ErrorType == "" {
					s.AssetType = det.Type()
					s.Detector = det.Type()
					s.IP = t.host
					s.Port = t.port
					s.ErrorType = "down"
				}

				mu.Lock()
				if prog != nil {
					prog.update(s)
				} else {
					printLine(s, res, *logFlag)
				}
				if enc != nil && !(*skipUnreach && s.ErrorType != "") {
					if err != nil {
						_ = enc.Encode(map[string]any{
							"asset_type": s.AssetType,
							"detector":   s.Detector,
							"ip":         s.IP,
							"port":       s.Port,
							"is_match":   false,
							"error_type": s.ErrorType,
							"error":      err.Error(),
							"ts":         time.Now().UTC().Format(time.RFC3339),
						})
					} else {
						_ = enc.Encode(res)
					}
				}
				mu.Unlock()
			}
		}()
	}

	emit := func(ip string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		for _, p := range ports {
			targets <- target{ip, p}
		}
		return nil
	}
	for _, expr := range posArgs {
		if err := targeting.ExpandTarget(expr, emit); err != nil {
			fmt.Fprintln(os.Stderr, "assetprobe: 目标展开失败:", expr, err)
		}
	}
	close(targets)
	wg.Wait()
	if prog != nil {
		prog.finish()
	}
}

func printLine(s detectors.Summary, res any, verbose bool) {
	tgt := fmt.Sprintf("%s:%d", s.IP, s.Port)
	if s.IsMatch {
		ver := s.Version
		if ver == "" {
			ver = "(未取到)"
		}
		fmt.Printf("%-22s %-11s version=%s\n", tgt, s.AssetType, ver)
	} else if s.ErrorType != "" {
		fmt.Printf("%-22s not-%s   %s\n", tgt, s.AssetType, reasonText(s.ErrorType))
	} else {
		fmt.Printf("%-22s not-%s   命中 %v，不满足白名单\n", tgt, s.AssetType, s.Matched)
	}
	if verbose {
		b, err := json.MarshalIndent(res, "  ", "  ")
		if err == nil {
			fmt.Printf("  evidence: %s\n", string(b))
		}
	}
}

func reasonText(et string) string {
	switch et {
	case "timeout":
		return "超时（unreachable）"
	case "connection_refused":
		return "端口关闭（connection_refused）"
	case "unreachable":
		return "不可达/被墙（unreachable）"
	default:
		return "探不到（down）"
	}
}

var valueFlags = map[string]bool{
	"-type": true, "--type": true, "-port": true, "--port": true,
	"-concurrency": true, "--concurrency": true, "-timeout": true, "--timeout": true,
	"-deadline": true, "--deadline": true, "-rate": true, "--rate": true,
	"-fingerprints": true, "--fingerprints": true, "-o": true,
}

func splitArgs(args []string) (flags, pos []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && valueFlags[a] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	return flags, pos
}

func parsePorts(s string) []uint16 {
	var ps []uint16
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := strconv.ParseUint(part, 10, 16); err == nil {
			ps = append(ps, uint16(p))
		}
	}
	return ps
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "assetprobe:", err)
	os.Exit(1)
}
