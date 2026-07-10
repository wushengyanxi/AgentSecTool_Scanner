# AgentSecTool Scanner — 资产测绘平台

AgentSecTool Scanner 是可扩展的资产测绘平台：发现候选目标，按资产类型调用探测器，只读验证目标实例，提取版本与证据，并归档到 SQLite 供看板和报告使用。OpenClaw 是当前内置探测器，对应 `asset_type=openclaw`。

## 组成

- `prober/detectors/`：Go 探测器接口与注册表；子目录放具体资产类型 detector。
- `prober/detectors/openclaw/`：OpenClaw detector 适配层，复用既有 `prober/openclaw` 探测与版本判定逻辑。
- `prober/cmd/assetprobe/`：平台级 runner，按 `--type` 调用对应探测器，输出 JSONL。
- `prober/cmd/ocprobe/`：OpenClaw 兼容 runner，保留旧工作流入口。
- `discovery/`：主动扫描与被动测绘源候选合并。
- `fofa/` / `clawsec/`：第三方测绘源数据拉取与本地库。
- `store/`：JSONL 入库，核心表为 `assets / observations / probe_records`，以 `asset_type:ip:port` 去重。
- `dashboard/`：本地资产测绘看板，支持时间窗口与资产类型过滤。

数据库按来源分库：`data/fofa/`、`data/clawsec/`、`data/scanner/` 各放各的，`data/` 已 gitignore。FOFA 等凭据只放环境变量或已 gitignore 的配置文件，不能硬编码。

## 依赖

Go 1.24+、Python 3.11+。Docker 只用于本地验证靶机。主动大规模扫描需 masscan 或 ZMap，并应在获授权的专用扫描主机上执行。

## 快速验证

本地测试不向公网发包：

```bash
make test
make demo
```

`make demo` 会执行：

```text
discovery(localhost) -> assetprobe --type openclaw -> store -> stats
```

如需手动跑最小链路：

```bash
python3 -m discovery --cidr 127.0.0.0/30 --ports 18789 --backend internal --allow-reserved --out candidates.csv
prober/bin/assetprobe --type openclaw --fingerprints fingerprints/fingerprints.json -o results.jsonl candidates.csv
python3 -m store --db data/scanner/scan_results.sqlite --in results.jsonl --stats
python3 -m dashboard --db data/scanner/scan_results.sqlite
```

看板默认地址：`http://127.0.0.1:8787/`。

## 探测入口

推荐入口是 `assetprobe`：

```bash
go -C prober build -o bin/assetprobe ./cmd/assetprobe
prober/bin/assetprobe --list-types
prober/bin/assetprobe --type openclaw --fingerprints fingerprints/fingerprints.json -o results.jsonl candidates.csv
```

目标可为精确 IPv4、CIDR、通配 IPv4、文件路径或 `-` 标准输入。`candidates.csv` 会按第一列取 IP，兼容 discovery/FOFA 导出的候选文件。

兼容入口 `ocprobe` 仍可使用：

```bash
go -C prober build -o bin/ocprobe ./cmd/ocprobe
prober/bin/ocprobe --fingerprints fingerprints/fingerprints.json -o results.jsonl candidates.csv
```

ZGrab2 OpenClaw 模块仍保留，用于需要复用 ZGrab2 并发、超时、限速和结构化输出的场景：

```bash
make zgrab
echo "1.2.3.4" | prober/bin/zgrab-openclaw openclaw --port 18789 \
  --blocklist-file=config/blocklist.txt --fingerprints fingerprints/fingerprints.json
```

## 扩展新资产类型

新增资产类型时只需要走四个落点：

1. 在 `prober/detectors/<type>/` 实现 detector，并通过 `detectors.Register()` 注册。
2. 输出结果至少实现平台字段：`asset_type`、`detector`、`ip`、`port`、`is_match`、`category`、`matched`、`error_type`、`ts`。
3. 如有版本或专用证据，继续写入 detector 自己的 JSON 字段；`store` 会保留通用字段，`probe_records` 可保存逐项请求/响应。
4. 如需人读报告，为该资产类型补充报告渲染逻辑；当前 OpenClaw 报告仍使用原有 C1/C2/C3 话术。

`category` 统一含义：

- `confirmed`：确认目标资产，且拿到版本或版本候选。
- `confirmed_no_version`：确认目标资产，但版本未知。
- `suspect`：命中特征但未达确认白名单，保留复扫或优化。

## 被动测绘源

FOFA 只给候选，项目自己的探测器负责最终确认与版本测定：

```bash
FOFA_EMAIL=... FOFA_KEY=... python3 -m fofa info
python3 -m fofa pull --db data/fofa/fofa.sqlite --full --before 2026-05-30
python3 -m fofa export --db data/fofa/fofa.sqlite --out candidates.csv --limit 500
prober/bin/assetprobe --type openclaw --fingerprints fingerprints/fingerprints.json -o results.jsonl candidates.csv
make load
```

ClawSec 是 OpenClaw 暴露面被动源，免凭据，按每日快照入库：

```bash
python3 -m clawsec info
python3 -m clawsec pull --db data/clawsec/clawsec.sqlite
python3 -m clawsec longlived --db data/clawsec/clawsec.sqlite --min-days 3
python3 -m clawsec overlap --db data/clawsec/clawsec.sqlite --fofa-db data/fofa/fofa.sqlite
```

第三方平台的版本标注只作为外部参考；本项目认可的确认结果以 `assetprobe` 实时探测结果为准。

## 主动扫描边界

主动扫描会对目标 IP 发起真实连接。大规模扫描必须具备授权、黑名单、限速、可识别出口和 abuse 联系方式，不应从开发笔记本直接扫任意公网地址段。

```bash
cp config/blocklist.example.txt config/blocklist.txt
sudo python3 -m discovery --cidr 0.0.0.0/0 --backend masscan --rate 20000 \
  --excludefile config/blocklist.txt --out candidates.csv
prober/bin/assetprobe --type openclaw --fingerprints fingerprints/fingerprints.json -o results.jsonl candidates.csv
python3 -m store --in results.jsonl --stats
```

## 安全约束

- 探测器默认只读，不发送改状态请求或配置写入请求。
- 凭据必须走环境变量或 gitignore 中的本地配置。
- `results.jsonl` 与 SQLite 可能包含目标响应原文，按敏感运行数据处理。
- 全网执行属于运营动作，必须有授权范围与合规前置。
