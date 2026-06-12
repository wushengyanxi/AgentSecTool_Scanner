// zgrab-openclaw：注册 openclaw 自定义模块并跑 ZGrab2 单模块扫描流程。
//
// 用法（与标准 zgrab2 一致）：
//   echo "1.2.3.4,18789" | zgrab-openclaw openclaw --port 18789 --fingerprints fingerprints/fingerprints.json
//   zgrab-openclaw openclaw -f candidates.csv -o results-zgrab.jsonl --senders 1000
//
// 这里不引入 github.com/zmap/zgrab2/bin，以免把所有默认模块（mysql/mongodb…）一并编入；
// 只复刻其单模块路径所需的几步。
package main

import (
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zflags"
	"github.com/zmap/zgrab2"
)

func main() {
	RegisterModule()

	_, moduleType, flag, err := zgrab2.ParseCommandLine(os.Args[1:])
	if err != nil {
		if fe, ok := err.(*flags.Error); ok && fe.Type == flags.ErrHelp {
			return // 输出 help 时 zflags 返回 error，正常退出
		}
		log.Fatalf("无法解析参数: %s", err)
	}

	mod := zgrab2.GetModule(moduleType)
	if mod == nil {
		log.Fatalf("未知模块: %s", moduleType)
	}
	scanner := mod.NewScanner()
	if err := scanner.Init(flag); err != nil {
		log.Fatalf("初始化扫描器失败: %s", err)
	}
	zgrab2.RegisterScan(moduleType, scanner)
	zgrab2.ValidateAndHandleFrameworkConfiguration()

	var wg sync.WaitGroup
	monitor := zgrab2.MakeMonitor(1, &wg, []string{moduleType})
	zgrab2.Process(monitor)
	monitor.Stop()
	wg.Wait()
}
