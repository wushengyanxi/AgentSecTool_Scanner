# OpenClaw 扫描器阶段说明（Round 1 归档）

本文归档平台化重构前的 OpenClaw 单资产类型扫描阶段，用于保留当时的功能边界、数据源和操作经验。现行平台入口、资产类型扩展方式和项目总览以 `README.md` 与 `docs/项目文档-v2.html` 为准。

## 阶段目标

该阶段围绕 OpenClaw 网关暴露面展开：发现候选实例、执行只读判定、尽力获取版本，并把结果落地到 SQLite。核心链路为：

```text
发现候选 -> 只读探测 -> 版本判断 -> JSONL -> SQLite
```

## 组成

以下路径是 Round 1 当时的目录口径，现行路径以根目录 `README.md` 和 `docs/项目文档-v2.html` 为准。

- `prober/`：OpenClaw 探测核心、`ocprobe` 兼容入口，以及当前平台级 `assetprobe` 入口。
- `discovery/`：主动 masscan/ZMap/internal 发现、FOFA/Shodan 被动种子、候选合并去重和黑名单过滤。
- `fofa/`：FOFA 候选拉取、断点续拉、时间窗、导出、省份统计和省份版本统计。
- `clawsec/`：ClawSec 平台快照拉取、长期有效实例分析、与 FOFA 隐位重叠分析和平台版本统计。
- `fingerprints/` 与 `fingerprint/`：OpenClaw 版本指纹库与采集工具。
- `store/`：把 JSONL 探测结果写入 `data/scanner/scan_results.sqlite`。

数据库按来源分库：`data/fofa/`、`data/clawsec/`、`data/scanner/`。旧 `scan.sqlite` 可通过 `python3 fingerprint/migrate_dbs.py` 迁移。

## 本地验证

启动本地 OpenClaw 靶机后，可运行：

```bash
make test
make demo
```

`make demo` 当前使用平台级入口完成本地链路：

```text
discovery(localhost) -> assetprobe --type openclaw -> store -> stats
```

## 探测入口

推荐入口是 `assetprobe`：

```bash
go -C prober build -o bin/assetprobe ./cmd/assetprobe
prober/bin/assetprobe --list-types
prober/bin/assetprobe --type openclaw --fingerprints fingerprints/fingerprints.json -o results.jsonl candidates.csv
```

`ocprobe` 保留为 OpenClaw 专用兼容入口。它不支持 `-f` 参数，目标文件作为位置参数传入，文件内每行一个目标；端口通过 `-port` 指定或读取配置：

```bash
go -C prober build -o bin/ocprobe ./cmd/ocprobe
prober/bin/ocprobe -port 18789 --fingerprints fingerprints/fingerprints.json -o results.jsonl targets.txt
```

ZGrab2 OpenClaw 模块仍保留，适合需要复用 ZGrab2 输入解析、并发、超时、限速和结构化输出的场景：

```bash
make zgrab
echo "1.2.3.4" | prober/bin/zgrab-openclaw openclaw --port 18789 \
  --blocklist-file=config/blocklist.txt --fingerprints fingerprints/fingerprints.json
```

`store` 兼容 `ocprobe` 扁平结果和 ZGrab2 envelope。

## 被动发现

被动发现只查询第三方测绘库，不向目标发包。凭据通过环境变量或本地配置提供，不硬编码在代码中：

```bash
FOFA_EMAIL=... FOFA_KEY=... SHODAN_API_KEY=... \
  python3 -m discovery --backend none --fofa --shodan --out candidates.csv

prober/bin/assetprobe --type openclaw --fingerprints fingerprints/fingerprints.json -o results.jsonl candidates.csv
python3 -m store --in results.jsonl --stats
```

## 主动扫描

主动扫描需要授权、专用扫描主机、黑名单、限速、可识别扫描源和 abuse 联系方式。不应从开发笔记本对任意公网地址段直接发起 SYN 扫描。

```bash
cp config/blocklist.example.txt config/blocklist.txt
sudo python3 -m discovery --cidr 0.0.0.0/0 --backend masscan --rate 20000 \
  --excludefile config/blocklist.txt --fofa --shodan --out candidates.csv

prober/bin/assetprobe --type openclaw --fingerprints fingerprints/fingerprints.json -o results.jsonl candidates.csv
python3 -m store --in results.jsonl --stats
```

## FOFA 工作流

FOFA 只提供候选，不作为项目确认版本的来源。版本以本项目探测器的实时结果为准。默认候选查询可通过 `--query` 覆盖。

```bash
make fofa-info
python3 -m fofa pull --full --before 2026-05-30
make fofa-provinces
make fofa-export LIMIT=500
prober/bin/assetprobe --type openclaw --fingerprints fingerprints/fingerprints.json -o results.jsonl candidates.csv
make load
make fofa-pv
```

FOFA 的额度由服务端约束；本地通过 `info/my` 查询剩余额度，通过 `--max-records` 控制单次拉取上限。时间窗使用 `--before` 和 `--after` 切分，断点续拉依赖 Search After 游标。

## ClawSec 工作流

ClawSec 提供公开的 OpenClaw 暴露面快照。平台隐藏 IP 的一位，携带平台自己的版本标注。其版本字段只是外部参考，项目确认结果仍以 `assetprobe --type openclaw` 或 `ocprobe` 的探测输出为准。

```bash
python3 -m clawsec info
python3 -m clawsec pull
python3 -m clawsec longlived --min-days 3
python3 -m clawsec overlap
python3 -m clawsec versions
```

`python3 -m clawsec pull` 会先续拉当前快照，随后进入 watch loop，按 `--watch-interval` 轮询平台更新；需要停止时使用 Ctrl-C。

## 安全边界

- 探测动作保持只读：执行 WS 升级和无鉴权 GET，不发送改状态帧。
- 默认支持超时、限速、黑名单和保留地址段排除。
- FOFA 等凭据通过环境变量或本地配置提供，并由 `.gitignore` 排除。
- 大规模扫描属于运营动作，必须在授权范围内执行。

## 后续方向

该阶段尚未形成完整的综合测绘平台。后续方向包括多资产类型 detector 注册、统一结果字段、版本到漏洞映射、地理与 ASN 富化、IPv6 hitlist、协同披露流程，以及适合大规模快照分析的后端存储。
