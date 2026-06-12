// openclaw 的 ZGrab2 自定义扫描模块：把已验证的探测核心 openclaw.Probe
// 薄封装进 ZGrab2 框架，复用框架的输入解析、并发、超时、限速、结构化输出与监控。
package main

import (
	"context"
	"fmt"

	oc "github.com/wushengyanxi/agentsectool-scanner/prober/openclaw"
	"github.com/zmap/zgrab2"
)

// Flags 是 openclaw 模块的命令行配置（框架填充）。
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	UseTLS           bool   `long:"tls" description:"用 TLS（wss/https）连接；端口 443/8443 自动启用"`
	FingerprintsPath string `long:"fingerprints" description:"指纹库 JSON 路径（用于隐式版本反推）"`
}

// Module 实现 zgrab2.ScanModule。
type Module struct{}

// Scanner 实现 zgrab2.Scanner。它薄封装 openclaw.Probe（核心自行拨号、只读）。
type Scanner struct {
	config            *Flags
	dialerGroupConfig *zgrab2.DialerGroupConfig
	fingerprints      *oc.FingerprintDB
}

// RegisterModule 把本模块注册进 ZGrab2 命令体系。
func RegisterModule() {
	var module Module
	if _, err := zgrab2.AddCommand("openclaw", "OpenClaw 网关探测", module.Description(), oc.DefaultPort, &module); err != nil {
		panic(err)
	}
}

func (m *Module) NewFlags() any              { return new(Flags) }
func (m *Module) NewScanner() zgrab2.Scanner { return new(Scanner) }
func (m *Module) Description() string {
	return "只读探测 OpenClaw 网关（WS connect.challenge + HTTP），判定并取版本"
}

func (f *Flags) Validate(_ []string) error { return nil }
func (f *Flags) Help() string              { return "" }

func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	s.config = f
	s.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
	}
	if f.FingerprintsPath != "" {
		db, err := oc.LoadFingerprintDB(f.FingerprintsPath)
		if err != nil {
			return fmt.Errorf("加载指纹库失败: %w", err)
		}
		s.fingerprints = db
	}
	return nil
}

func (s *Scanner) InitPerSender(_ int) error                       { return nil }
func (s *Scanner) GetName() string                                 { return s.config.Name }
func (s *Scanner) GetTrigger() string                              { return s.config.Trigger }
func (s *Scanner) Protocol() string                                { return "openclaw" }
func (s *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig { return s.dialerGroupConfig }
func (s *Scanner) GetScanMetadata() any                            { return nil }

// Scan 调用探测核心。核心自行拨号并保持只读（绝不发 connect/config.apply）；
// 这里不使用框架的 dialerGroup，因此用 _ 忽略。
func (s *Scanner) Scan(ctx context.Context, _ *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	// 我们扫的是 IP；IP 在就用 IP，否则退回域名。ZGrab2 的 CSV 列是 IP[,domain,tag]，
	// 端口来自 --port，不在行内。
	host := target.Domain
	if target.IP != nil {
		host = target.IP.String()
	}
	port := uint16(target.Port)
	if port == 0 {
		port = uint16(s.config.Port)
	}
	if port == 0 {
		port = oc.DefaultPort
	}
	tlsOn := s.config.UseTLS || port == 443 || port == 8443

	r := oc.Probe(ctx, host, port, oc.Options{
		TLS:          tlsOn,
		Timeout:      s.config.TargetTimeout,
		Fingerprints: s.fingerprints,
	})
	if r.IsOpenClaw {
		return zgrab2.SCAN_SUCCESS, r, nil
	}
	// 非 OpenClaw：仍把结果带出便于审计，状态标为 protocol-error。
	return zgrab2.SCAN_PROTOCOL_ERROR, r, nil
}
