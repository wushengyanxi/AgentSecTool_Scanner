// ocprobe 是 openclaw 探测核心的命令行 runner。
//
// 目标输入四种形式（自动识别）：精确 IP / 文件路径（每行一个目标）/ 通配 IP（123.*.*.4）/
// CIDR（203.0.113.0/24）。对每个目标做只读探测、二元研判、取版本，默认逐行打印结论，
// -l 打印完整研判依据，并把含完整请求/响应的 JSONL 落盘（供 store 入库与 --report 出报告）。
package main

import (
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
	cfg := loadConfig() // config.toml 的默认值；找不到用内置默认

	var (
		portsArg = flag.String("port", "", "端口，逗号分隔多个（默认取 config.toml）")
		conc     = flag.Int("concurrency", int(cfg.concurrency), "全局并发探测数")
		timeout  = flag.Duration("timeout", cfg.timeoutPerIP, "单 IP 探测超时")
		deadline = flag.Duration("deadline", cfg.deadline, "整个任务的总时长上限（0=不限）")
		rate     = flag.Int("rate", int(cfg.rate), "单个目标 IP 的每秒发包上限（0=不限）")
		logFlag  = flag.Bool("l", cfg.verbose > 0, "详细日志：打印每个 IP 的完整研判依据")
		fpPath   = flag.String("fingerprints", "", "指纹库 JSON 路径（隐式版本反推）")
		outPath  = flag.String("o", "", "JSONL 输出文件（含完整请求/响应，供入库）；缺省不落盘")
		tlsOn    = flag.Bool("tls", false, "强制所有目标用 TLS（缺省按端口自动）")
		_        = flag.String("report", "", "从已落盘结果生成报告，按文件名后缀定格式（由 store 实现，占位）")
		_        = flag.Bool("resume", false, "断点续扫（占位）")
	)
	// 像 nmap 那样允许目标与选项混排：先把位置参数（目标）与选项分开，再解析选项。
	flagArgs, posArgs := splitArgs(os.Args[1:])
	_ = flag.CommandLine.Parse(flagArgs)

	ports := cfg.ports
	if *portsArg != "" {
		ports = parsePorts(*portsArg)
	}
	if len(ports) == 0 {
		fail(fmt.Errorf("未指定端口"))
	}

	// 目标表达式：位置参数（可多个）。文件路径由 ExpandTarget 的文件分支处理。
	exprs := posArgs
	if len(exprs) == 0 {
		fail(fmt.Errorf("用法：ocprobe [选项] <目标...>\n  目标可为：精确IP / 文件路径 / 通配IP(123.*.*.4) / CIDR(203.0.113.0/24)"))
	}

	var fpdb *oc.FingerprintDB
	if *fpPath != "" {
		db, err := oc.LoadFingerprintDB(*fpPath)
		if err != nil {
			fail(err)
		}
		fpdb = db
	}

	var jsonl *os.File
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fail(err)
		}
		defer f.Close()
		jsonl = f
	}

	// 任务总超时
	ctx := context.Background()
	if *deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *deadline)
		defer cancel()
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
		minInterval = time.Second / time.Duration(*rate) // 单 IP 发包最小间隔
	}

	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range targets {
				if ctx.Err() != nil { // 任务总超时到点：停止取新目标
					return
				}
				if minInterval > 0 {
					time.Sleep(minInterval) // 单 IP 限速兜底（单台请求很少，主要防重试风暴）
				}
				pctx, cancel := context.WithTimeout(ctx, *timeout+2*time.Second)
				useTLS := *tlsOn || t.port == 443 || t.port == 8443 || t.port == 9443
				res := oc.Probe(pctx, t.host, t.port, oc.Options{TLS: useTLS, Timeout: *timeout, Fingerprints: fpdb})
				cancel()
				mu.Lock()
				printLine(res, *logFlag) // 默认终端输出
				if enc != nil {
					_ = enc.Encode(res) // 含完整请求/响应，落盘供入库
				}
				mu.Unlock()
			}
		}()
	}

	// 展开所有目标表达式 × 所有端口，喂入队列。
	emit := func(ip string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		for _, p := range ports {
			targets <- target{ip, p}
		}
		return nil
	}
	for _, expr := range exprs {
		if err := ExpandTarget(expr, emit); err != nil {
			fmt.Fprintln(os.Stderr, "ocprobe: 目标展开失败:", expr, err)
		}
	}
	close(targets)
	wg.Wait()
}

// printLine 打印单个目标的终端结果。默认一行结论；-l 时附完整研判依据。
func printLine(r oc.Result, verbose bool) {
	tgt := fmt.Sprintf("%s:%d", r.IP, r.Port)
	if r.IsOpenClaw {
		ver := r.Version
		if len(r.VersionCandidates) > 0 {
			ver = strings.Join(r.VersionCandidates, "|")
		}
		if ver == "" {
			ver = "(未取到)"
		}
		fmt.Printf("%-22s OpenClaw   version=%s\n", tgt, ver)
	} else if r.ErrorType != "" {
		fmt.Printf("%-22s not-openclaw   %s\n", tgt, reasonText(r.ErrorType))
	} else {
		fmt.Printf("%-22s not-openclaw   命中 %v，不满足白名单\n", tgt, r.Matched)
	}
	if verbose {
		printVerbose(r)
	}
}

func printVerbose(r oc.Result) {
	fmt.Printf("  research: verdict=%v rule=%s matched=%v\n", r.IsOpenClaw, r.Rule, r.Matched)
	for _, p := range r.Evidence.Probes {
		hit := "miss"
		if p.Hit {
			hit = "HIT"
		}
		first := p.Response
		if i := strings.IndexByte(first, '\n'); i >= 0 {
			first = first[:i]
		}
		if len(first) > 70 {
			first = first[:70]
		}
		fmt.Printf("    [%s] %-4s %s\n", p.ID, hit, first)
	}
}

func reasonText(et string) string {
	switch et {
	case oc.ErrTimeout:
		return "超时（unreachable）"
	case oc.ErrRefused:
		return "端口关闭（connection_refused）"
	case oc.ErrUnreach:
		return "不可达/被墙（unreachable）"
	default:
		return "探不到（down）"
	}
}

// 需要带值的布尔选项之外的选项集合（用于 splitArgs 判断下一个 token 是不是该选项的值）。
// 这些选项形如 --opt value，其后的 token 是值而非目标。布尔选项（-l/--tls/--resume）不吃值。
var valueFlags = map[string]bool{
	"-port": true, "--port": true, "-concurrency": true, "--concurrency": true,
	"-timeout": true, "--timeout": true, "-deadline": true, "--deadline": true,
	"-rate": true, "--rate": true, "-fingerprints": true, "--fingerprints": true,
	"-o": true, "-report": true, "--report": true,
}

// splitArgs 把 nmap 风格的混排参数分成「选项」与「目标」两组，使目标可出现在任意位置。
func splitArgs(args []string) (flags, pos []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			// 形如 --opt=value 自带值；否则若是吃值选项，下一个 token 是它的值。
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
	fmt.Fprintln(os.Stderr, "ocprobe:", err)
	os.Exit(1)
}
