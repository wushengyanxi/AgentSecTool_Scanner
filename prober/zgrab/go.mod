// 独立模块：隔离 zgrab2 的庞大依赖，不污染零依赖、已验证的探测核心（../，package openclaw）。
module github.com/wushengyanxi/agentsectool-scanner/prober/zgrab

go 1.24.0

toolchain go1.24.3

require (
	github.com/sirupsen/logrus v1.9.3
	github.com/wushengyanxi/agentsectool-scanner/prober v0.0.0
	github.com/zmap/zflags v1.4.0-beta.1.0.20251126025438-ec78c6d2f8e9
	github.com/zmap/zgrab2 v1.0.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/censys/cidranger v1.1.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/weppos/publicsuffix-go v0.40.3-0.20250617082559-9b2e24a9e482 // indirect
	github.com/zmap/zcrypto v0.0.0-20250618174828-7ca6a82cf2d4 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
)

replace github.com/wushengyanxi/agentsectool-scanner/prober => ../
