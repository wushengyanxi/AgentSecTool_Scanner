# AgentSecTool Scanner — OpenClaw 公网暴露扫描器

在公网范围发现暴露的 OpenClaw 网关、可靠判定并尽力取版本。本轮（Round 1）实现**扫描核心**：
发现（全网能力）→ 只读判定 → 取版本 → 落地 SQLite。扫描所依据的服务特征、判定与置信度
逻辑、以及让单 IP 研判更精准的路径，见根目录文档 `扫描研判依据与精准化路径.html`。

## 组成

- `prober/`（Go）— openclaw 探测核心 + `cmd/ocprobe` runner：WS `connect.challenge` + HTTP 簇的只读探测、跨表面置信判定、取版本（疏防直读 `serverVersion` / 已防隐式反推）。
- `discovery/`（Python）— 主动 masscan/ZMap（任意 CIDR，直至全网）+ FOFA 被动种子 + 合并去重 + 黑名单。
- `fofa/` / `clawsec/`（Python）— 两个被动测绘源，候选入 `scan.sqlite`：`fofa/` 拉 FOFA（需凭据、按额度）；`clawsec/` 拉 ClawSec 高校暴露面平台（免凭据、频繁更新、带平台自己的版本判定，可与本项目探测器双源对比）。
- `fingerprints/` + `harness/` — 版本指纹库与采集 harness（逐版本起容器记签名）。
- `sink/`（Python）— `results.jsonl` → SQLite（`assets` 资产登记 + `observations` 时序观测）。

## 依赖

Go 1.24+、Python 3.11+、Docker（仅本地验证靶机）。全网主动扫描需 masscan 或 ZMap（root）。
扫描器整条流水线 + SQLite 文件都跑在**本地宿主机**；唯一的容器是被扫的 OpenClaw 靶机。

## 快速验证（本地，不向公网发包）

1）起靶机（被扫的 OpenClaw）：

```
docker run -d --name oc-fp -p 18789:18789 \
  -e OPENCLAW_GATEWAY_TOKEN=$(openssl rand -hex 32) \
  openclaw:local node dist/index.js gateway --bind lan --port 18789 --allow-unconfigured
```

2）一键测试 + 全链：

```
make test     # go 测试（含只读不变量）+ python 单测
make demo     # 发现(localhost) → 探测 → 落地 → 统计
```

## 两种探测器

- **ocprobe**（轻量，多端口原生）：`prober/bin/ocprobe -f candidates.csv ...`，输入每行 `IP[,port]`。
- **zgrab-openclaw**（ZGrab2 自定义模块，生产形态）：复用 ZGrab2 框架的并发、超时、限速、结构化输出与监控。输入每行 **IP**，端口走 `--port`（多端口需按端口分别跑）；首次构建会拉 zgrab2 依赖。

```
make zgrab                                   # 构建 ZGrab2 二进制
echo "1.2.3.4" | prober/bin/zgrab-openclaw openclaw --port 18789 \
  --blocklist-file=config/blocklist.txt --fingerprints fingerprints/fingerprints.json
```

两者输出都能直接喂 `sink`（sink 同时认 ocprobe 扁平格式与 ZGrab2 信封格式）。

## 真实公网扫描

### 被动发现（非侵入，推荐先做）

只查第三方测绘库，不向任何目标发包。凭据走环境变量，绝不硬编码。

```
# FOFA（境内覆盖最佳）/ Shodan（全球）；二者择一或并用
FOFA_EMAIL=... FOFA_KEY=... SHODAN_API_KEY=... \
  python3 -m discovery --backend none --fofa --shodan --out candidates.csv
# 探测（只读）+ 落地
prober/bin/ocprobe -f candidates.csv --fingerprints fingerprints/fingerprints.json -o results.jsonl
python3 -m sink --db scan.sqlite --in results.jsonl --stats
```

Censys / Quake / ZoomEye 留待按同样的可插拔结构扩展。

### 主动全网扫描（专用 Linux 扫描主机，需授权）

需 sudo + 黑名单 + 限速 + 可识别扫描源（rDNS、说明页、abuse 联系人）。
不应从开发笔记本对任意公网地址段直接发 SYN。

```
cp config/blocklist.example.txt config/blocklist.txt   # 全网必须排除保留网段
sudo python3 -m discovery --cidr 0.0.0.0/0 --backend masscan --rate 20000 \
     --excludefile config/blocklist.txt --fofa --shodan --out candidates.csv
prober/bin/ocprobe -f candidates.csv --fingerprints fingerprints/fingerprints.json -o results.jsonl
python3 -m sink --db scan.sqlite --in results.jsonl --stats
```

## FOFA 中国大陆普查工作流（额度受限）

FOFA 只给候选、不给版本——版本由本项目探测器自取。默认候选查询（实测 `country="CN"`）：
`(title="OpenClaw" || icon_hash="-805544463")`——title 用宽匹配（FOFA 的 `=` 即"包含"）多召回改名/汉化实例，
误报交给逐台探测过滤；可叠加 `app="OpenClaw"`（FOFA 产品指纹）。查询不写死，`--query` 可传完整 FOFA 语句覆盖。

额度策略（绑定约束 = 10 万条数据/月，查询次数不紧张）：

- 额度由 FOFA 服务端强制（超了直接拒绝）：本地不记账，只用 `info/my` 看剩余、`--max-records` 给单次封顶；额度耗尽时优雅停并续拉；FOFA 限速自动退避。
- **普查切分用时间窗**：`--before/--after`（FOFA 操作符，过滤 lastupdatetime）切出确定性、可重复的块——先拉新鲜窗（`after`，更可能在线）。`fofa_state` 的 Search After 游标只管**一次运行内**的断点续（重启可续、按查询语句校验）；跨月/跨设备靠"重跑同一窗口查询 + 按 `(ip,port)` 去重累积"，不依赖游标长期有效。
- 版本新鲜度靠自有探测器复扫候选（不耗 FOFA 额度）。

凭据先 `cp fofa/fofa.example.ini fofa/fofa.ini` 填入（已 gitignore），或用环境变量 `FOFA_EMAIL` / `FOFA_KEY`。
**命令在项目根目录跑**（不是 `fofa/` 内，否则 `No module named fofa`）：

```
make fofa-info                                   # 账号 / 剩余额度 + 默认查询
python3 -m fofa pull --db scan.sqlite --full --before 2026-05-30   # 时间窗全量（带进度、可续）
make fofa-provinces                              # 按省候选数量
make fofa-export LIMIT=500                       # 导出候选 → candidates.csv
prober/bin/ocprobe -f candidates.csv --fingerprints fingerprints/fingerprints.json -o results.jsonl
make load                                        # 入库（assets / observations）
make fofa-pv                                     # 按省 × 版本（资产规划）
```

绝不硬编码凭据。全量普查 + 批量探测属运营动作，在授权扫描主机上限速、可识别地跑。

## ClawSec 测绘平台拉取（与 FOFA 平级的被动源）

ClawSec（`clawsec.tcode.com.cn`）是高校做的 OpenClaw 公网暴露面测绘平台，公开、频繁更新。
免凭据；IP 隐藏一位（`masked_ip`，补全/枚举留给下游探测）；携带平台自己的版本判定（`their_version`）
与历史漏洞标注——入 `scan.sqlite` 的 `clawsec_instances` 表，与 `fofa_candidates` 同库可 SQL 交叉。
平台数据非实时（带 `lastScanTime`），其版本字段可能滞后；以本项目探测器的实时探测为准、可做双源对比。

```
python3 -m clawsec info                          # 平台汇总计数（总量 / Active / 境内 / 最后扫描时间）
python3 -m clawsec pull --db scan.sqlite         # 拉境内 Active 入库（拉完为止，可续；守 80次/15min 限速）
python3 -m clawsec pull --scope all              # 拉全部（境内 + 海外）
python3 -m clawsec overlap --db scan.sqlite      # 与 fofa_candidates 的隐位重叠统计
python3 -m clawsec versions --db scan.sqlite     # 按平台标注版本统计
```

命令在项目根目录跑。遇服务端限流（429）自动按 `Retry-After` 等待续拉，无人值守。

## 安全与合规（内建）

- **只读、良性**：探测只做 WS 升级 + 无鉴权 GET，绝不发 `connect` / `config.apply` 或任何改状态帧（单测固化）。
- **礼貌**：每 IP 限速，远低于服务端 `MAX_PREAUTH_CONNECTIONS_PER_IP=32`；默认排除保留/私有网段；黑名单与 opt-out 走 `config/blocklist.txt`。
- **凭据**：FOFA 等凭据走环境变量/配置，绝不硬编码，已 `gitignore`。
- 全网执行属运营动作，需授权、专用出口 IP 与合规前置。

## 扩充版本指纹库

```
python3 harness/build_corpus.py --image <openclaw 镜像> --version <版本号>
```

## 本轮未做（后续）

ZGrab2 模块封装（生产形态，本轮以功能等价的 `ocprobe` 交付）、版本→CVE 映射、暴露面板、ClickHouse/PostgreSQL、Geo/ASN 与省市富化、IPv6 hitlist、协同披露。
