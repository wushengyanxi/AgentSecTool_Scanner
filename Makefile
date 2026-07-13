ROOT    := $(shell pwd)
PROBER  := $(ROOT)/prober
ASSETPROBE := $(PROBER)/bin/assetprobe
OCPROBE := $(PROBER)/bin/ocprobe
FP      := $(PROBER)/fingerprints/openclaw.json
DISCOVERY_CANDIDATES := $(ROOT)/src/agentsectool_scanner/discovery/output/candidates.csv
FOFA_CANDIDATES      := $(ROOT)/tools/fofa/output/candidates.csv
RESULTS ?= $(PROBER)/output/results.jsonl
CANDIDATES ?= $(DISCOVERY_CANDIDATES)
FOFA_DB    := $(ROOT)/tools/fofa/data/fofa.sqlite
CLAWSEC_DB := $(ROOT)/tools/clawsec/data/clawsec.sqlite
SCANNER_DB := $(ROOT)/src/agentsectool_scanner/store/data/scan_results.sqlite
ZB      := $(PROBER)/bin/zgrab-openclaw
export PYTHONPATH := $(ROOT)/src:$(ROOT)

# 发现参数（可覆盖）：make discover CIDR=1.2.3.0/24 BACKEND=masscan
CIDR    ?= 127.0.0.0/30
PORTS   ?= 18789
BACKEND ?= internal

.PHONY: prober assetprobe ocprobe zgrab test discover probe probe-zgrab load stats demo \
        fofa-info fofa-pull fofa-provinces fofa-export fofa-pv \
        clawsec-info clawsec-pull clawsec-longlived clawsec-overlap clean

prober: assetprobe ocprobe

assetprobe:
	go -C $(PROBER) build -o bin/assetprobe ./cmd/assetprobe

ocprobe:
	go -C $(PROBER) build -o bin/ocprobe ./cmd/ocprobe

test: prober
	go -C $(PROBER) test ./...
	python3 -m unittest agentsectool_scanner.discovery.tests.test_discovery agentsectool_scanner.store.tests.test_store agentsectool_scanner.progress.tests.test_blocks tools.fofa.tests.test_pull

discover:
	python3 -m agentsectool_scanner.discovery --cidr $(CIDR) --ports $(PORTS) --backend $(BACKEND) --out $(CANDIDATES)

probe: assetprobe
	$(ASSETPROBE) --type openclaw --fingerprints $(FP) -o $(RESULTS) $(CANDIDATES)

# 生产形态：ZGrab2 自定义模块（首次构建较慢，会拉 zgrab2 依赖）
zgrab:
	go -C $(PROBER)/zgrab build -o $(ZB) .

# 用 ZGrab2 模块探测（输入每行 IP，端口走 --port；多端口需按端口分别跑）
probe-zgrab: zgrab
	mkdir -p $(dir $(RESULTS))
	cut -d, -f1 $(CANDIDATES) | sort -u | $(ZB) openclaw --port 18789 --blocklist-file= --fingerprints $(FP) -o $(RESULTS)

load:
	python3 -m agentsectool_scanner.store --db $(SCANNER_DB) --in $(RESULTS)

stats:
	python3 -m agentsectool_scanner.store --db $(SCANNER_DB) --stats

# 端到端 demo（需先起靶机 oc-fp，见 README）
demo: assetprobe
	python3 -m agentsectool_scanner.discovery --cidr 127.0.0.0/30 --ports 18789 --backend internal --allow-reserved --out $(CANDIDATES)
	$(ASSETPROBE) --type openclaw --fingerprints $(FP) -o $(RESULTS) $(CANDIDATES)
	python3 -m agentsectool_scanner.store --db $(SCANNER_DB) --in $(RESULTS)
	python3 -m agentsectool_scanner.store --db $(SCANNER_DB) --stats

# --- FOFA 工作流（凭据走环境变量 FOFA_EMAIL / FOFA_KEY）---
fofa-info:
	python3 -m tools.fofa info
# make fofa-pull [MAX=200] [DELTA=1] [BEFORE=2026-05-30] [AFTER=2026-05-01] [QUERY='...']
fofa-pull:
	python3 -m tools.fofa pull --db $(FOFA_DB) $(if $(DELTA),--delta,--full) $(if $(MAX),--max-records $(MAX),) $(if $(BEFORE),--before $(BEFORE),) $(if $(AFTER),--after $(AFTER),) $(if $(QUERY),--query $(QUERY),)
fofa-provinces:
	python3 -m tools.fofa provinces --db $(FOFA_DB)
fofa-export:
	python3 -m tools.fofa export --db $(FOFA_DB) --out $(FOFA_CANDIDATES) $(if $(LIMIT),--limit $(LIMIT),)
fofa-pv:
	python3 -m tools.fofa province-versions --db $(FOFA_DB) --scanner-db $(SCANNER_DB)

clean:
	rm -rf $(ROOT)/src/agentsectool_scanner/discovery/output \
	       $(ROOT)/src/agentsectool_scanner/store/data \
	       $(ROOT)/prober/output \
	       $(ROOT)/tools/fofa/data $(ROOT)/tools/fofa/output \
	       $(ROOT)/tools/clawsec/data \
	       $(ROOT)/tools/scope/output \
	       $(ROOT)/tools/scan_test/output \
	       $(ROOT)/tools/fingerprint/output

# --- ClawSec 每日全量快照工作流（免凭据）---
clawsec-info:
	python3 -m tools.clawsec info
clawsec-pull:
	python3 -m tools.clawsec pull --db $(CLAWSEC_DB) $(if $(SCOPE),--scope $(SCOPE),)
clawsec-longlived:
	python3 -m tools.clawsec longlived --db $(CLAWSEC_DB) $(if $(MINDAYS),--min-days $(MINDAYS),)
clawsec-overlap:
	python3 -m tools.clawsec overlap --db $(CLAWSEC_DB) --fofa-db $(FOFA_DB)
