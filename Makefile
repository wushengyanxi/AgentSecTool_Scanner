ROOT    := $(shell pwd)
PROBER  := $(ROOT)/prober
OCPROBE := $(PROBER)/bin/ocprobe
FP      := $(ROOT)/fingerprints/fingerprints.json
FOFA_DB    := $(ROOT)/data/fofa/fofa.sqlite
CLAWSEC_DB := $(ROOT)/data/clawsec/clawsec.sqlite
SCANNER_DB := $(ROOT)/data/scanner/scan_results.sqlite
ZB      := $(PROBER)/bin/zgrab-openclaw
export PYTHONPATH := $(ROOT)

# 发现参数（可覆盖）：make discover CIDR=1.2.3.0/24 BACKEND=masscan
CIDR    ?= 127.0.0.0/30
PORTS   ?= 18789
BACKEND ?= internal

.PHONY: prober zgrab test discover probe probe-zgrab load stats demo \
        fofa-info fofa-pull fofa-provinces fofa-export fofa-pv \
        clawsec-info clawsec-pull clawsec-longlived clawsec-overlap clean

prober:
	go -C $(PROBER) build -o bin/ocprobe ./cmd/ocprobe

test: prober
	go -C $(PROBER) test ./...
	python3 -m unittest discovery.tests.test_discovery store.tests.test_store progress.tests.test_blocks fofa.tests.test_pull

discover:
	python3 -m discovery --cidr $(CIDR) --ports $(PORTS) --backend $(BACKEND) --out candidates.csv

probe: prober
	$(OCPROBE) -f candidates.csv --fingerprints $(FP) -o results.jsonl

# 生产形态：ZGrab2 自定义模块（首次构建较慢，会拉 zgrab2 依赖）
zgrab:
	go -C $(PROBER)/zgrab build -o $(ZB) .

# 用 ZGrab2 模块探测（输入每行 IP，端口走 --port；多端口需按端口分别跑）
probe-zgrab: zgrab
	cut -d, -f1 candidates.csv | sort -u | $(ZB) openclaw --port 18789 --blocklist-file= --fingerprints $(FP) -o results.jsonl

load:
	python3 -m store --db $(SCANNER_DB) --in results.jsonl

stats:
	python3 -m store --db $(SCANNER_DB) --stats

# 端到端 demo（需先起靶机 oc-fp，见 README）
demo: prober
	python3 -m discovery --cidr 127.0.0.0/30 --ports 18789 --backend internal --allow-reserved --out candidates.csv
	$(OCPROBE) -f candidates.csv --fingerprints $(FP) -o results.jsonl
	python3 -m store --db $(SCANNER_DB) --in results.jsonl
	python3 -m store --db $(SCANNER_DB) --stats

# --- FOFA 工作流（凭据走环境变量 FOFA_EMAIL / FOFA_KEY）---
fofa-info:
	python3 -m fofa info
# make fofa-pull [MAX=200] [DELTA=1] [BEFORE=2026-05-30] [AFTER=2026-05-01] [QUERY='...']
fofa-pull:
	python3 -m fofa pull --db $(FOFA_DB) $(if $(DELTA),--delta,--full) $(if $(MAX),--max-records $(MAX),) $(if $(BEFORE),--before $(BEFORE),) $(if $(AFTER),--after $(AFTER),) $(if $(QUERY),--query $(QUERY),)
fofa-provinces:
	python3 -m fofa provinces --db $(FOFA_DB)
fofa-export:
	python3 -m fofa export --db $(FOFA_DB) --out candidates.csv $(if $(LIMIT),--limit $(LIMIT),)
fofa-pv:
	python3 -m fofa province-versions --db $(FOFA_DB)

clean:
	rm -f candidates.csv results.jsonl
	rm -rf $(ROOT)/data

# --- ClawSec 每日全量快照工作流（免凭据）---
clawsec-info:
	python3 -m clawsec info
clawsec-pull:
	python3 -m clawsec pull --db $(CLAWSEC_DB) $(if $(SCOPE),--scope $(SCOPE),)
clawsec-longlived:
	python3 -m clawsec longlived --db $(CLAWSEC_DB) $(if $(MINDAYS),--min-days $(MINDAYS),)
clawsec-overlap:
	python3 -m clawsec overlap --db $(CLAWSEC_DB) --fofa-db $(FOFA_DB)
