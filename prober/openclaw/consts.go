package openclaw

// 已实测确认的 OpenClaw 指纹常量（容器实测，版本 2026.5.17；
// 信号与置信度研判机制详见 docs/扫描器优化与研判机制.html §02–§03）。

const (
	// FaviconMD5 是 /favicon.ico 的 md5，跨版本稳定，是版本无关的品牌指纹。
	FaviconMD5 = "f58854f6450618729679ad33622bebaf"

	// TitleMarker 是首页 <title> 文本。
	TitleMarker = "OpenClaw Control"

	// ControlUIConfigPath 是带版本（serverVersion）的配置端点：auth=none 时 200，否则 401。
	ControlUIConfigPath = "/__openclaw/control-ui-config.json"

	// WSChallengeEvent 是 WebSocket 连接后服务端立即下发的事件名（最强判定信号）。
	WSChallengeEvent = "connect.challenge"

	// DefaultPort 是 OpenClaw 网关默认端口。
	DefaultPort = 18789

	// scannerUserAgent 让扫描源可识别（公民化扫描）。规模化前应在运行层注入 abuse 链接。
	scannerUserAgent = "AgentSecTool-OpenClaw-Scanner/0.1 (+research; detection-only)"
)

// detectConfidenceFloor 是兜底置信阈值（判定主要靠"WS 挑战 或 ≥2 个跨表面信号"，见 signals.go）。
const detectConfidenceFloor = 0.90
