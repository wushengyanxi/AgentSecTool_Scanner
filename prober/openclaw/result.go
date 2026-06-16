package openclaw

// 测试项编号（与 docs/扫描器优化与研判机制.html §04 的白名单一致）。
// 证据级别：T1 确证级；T2/T3/T4 强证据；T5/T6/T7 弱证据。
const (
	T1 = "T1" // control-ui-config 200 + serverVersion（确证级，服务端运行时自报）
	T2 = "T2" // WS connect.challenge（强证据，WS 协议面）
	T3 = "T3" // control-ui-config 401（强证据，HTTP 路由面，端点存在）
	T4 = "T4" // /healthz 特征体（强证据，HTTP 路由面）
	T5 = "T5" // favicon MD5（弱证据，可静态伪造）
	T6 = "T6" // 首页 title（弱证据，可静态伪造）
	T7 = "T7" // 响应头三件套（弱证据，常见框架默认）
)

// ErrorType 区分探测失败的原因（默认终端输出与诊断用）。
const (
	ErrTimeout    = "timeout"            // 单 IP 探测超时
	ErrRefused    = "connection_refused" // 端口关闭
	ErrUnreach    = "unreachable"        // 不可达 / 被墙
	ErrDown       = "down"               // 其它「探不到」
)

// ProbeRecord 是单个测试项的完整请求/响应原文记录（入库用，供报告复查）。
type ProbeRecord struct {
	ID       string `json:"id"`       // T1..T7
	Request  string `json:"request"`  // 完整请求原文（请求行 + 头）
	Response string `json:"response"` // 完整响应原文（状态行 + 头 + 体，截断至上限）
	Hit      bool   `json:"hit"`      // 该测试项是否命中
}

// Result 是单个目标的探测结果，序列化为 JSONL 一行。
type Result struct {
	IP         string `json:"ip"`
	Port       uint16 `json:"port"`
	IsOpenClaw bool   `json:"is_openclaw"` // 二元研判 verdict（True/False）
	// Matched 列出命中的测试项（如 ["T1","T2","T4"]）。
	Matched []string `json:"matched,omitempty"`
	// Rule 是触发的白名单条件（"C1" / "C2"），False 时为空。
	Rule              string   `json:"rule,omitempty"`
	Version           string   `json:"version,omitempty"`
	VersionSource     string   `json:"version_source,omitempty"` // direct | implicit | implicit-range
	VersionCandidates []string `json:"version_candidates,omitempty"`
	TLS               bool     `json:"tls"`
	Evidence          Evidence `json:"evidence"`
	// ErrorType 区分探不到的原因（timeout/connection_refused/unreachable/down），探到则为空。
	ErrorType string `json:"error_type,omitempty"`
	Error     string `json:"error,omitempty"`
	TS        string `json:"ts"` // RFC3339 UTC
}

// Evidence 收集判定与取版本所依据的原始观测，以及每个测试项的完整请求/响应。
type Evidence struct {
	WSChallenge     bool          `json:"ws_challenge"`
	HealthzMatch    bool          `json:"healthz_match"`
	HeaderTriplet   bool          `json:"header_triplet"`
	Title           string        `json:"title,omitempty"`
	FaviconMD5      string        `json:"favicon_md5,omitempty"`
	ControlUIStatus int           `json:"control_ui_status,omitempty"`
	CSP             string        `json:"-"` // 原文不入库，仅用于求哈希
	CSPSHA256       string        `json:"csp_sha256,omitempty"`
	AssetHashes     []string      `json:"asset_hashes,omitempty"`
	ServerVersion   string        `json:"server_version,omitempty"`
	Probes          []ProbeRecord `json:"probes,omitempty"` // 每个测试项的完整请求/响应原文
}
