package openclaw

// Result 是单个目标的探测结果，序列化为 JSONL 一行。
type Result struct {
	IP            string   `json:"ip"`
	Port          uint16   `json:"port"`
	IsOpenClaw    bool     `json:"is_openclaw"`
	Confidence    float64  `json:"confidence"`
	Signals       []string `json:"signals"`
	Version       string   `json:"version,omitempty"`
	VersionSource string   `json:"version_source,omitempty"` // direct | implicit
	TLS           bool     `json:"tls"`
	Evidence      Evidence `json:"evidence"`
	Error         string   `json:"error,omitempty"`
	TS            string   `json:"ts"` // RFC3339 UTC
}

// Evidence 收集判定与取版本所依据的原始观测。
type Evidence struct {
	WSChallenge     bool     `json:"ws_challenge"`
	HealthzMatch    bool     `json:"healthz_match"`
	HeaderTriplet   bool     `json:"header_triplet"`
	Title           string   `json:"title,omitempty"`
	FaviconMD5      string   `json:"favicon_md5,omitempty"`
	ControlUIStatus int      `json:"control_ui_status,omitempty"`
	CSP             string   `json:"-"` // 原文不入库，仅用于求哈希
	CSPSHA256       string   `json:"csp_sha256,omitempty"`
	AssetHashes     []string `json:"asset_hashes,omitempty"`
	ServerVersion   string   `json:"server_version,omitempty"`
}
