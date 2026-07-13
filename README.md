# AgentSecTool Scanner — 资产测绘平台

AgentSecTool Scanner 是可扩展的资产测绘平台：发现候选目标，按资产类型调用探测器，只读验证目标实例，提取版本与证据，并归档到 SQLite 供看板和报告使用。OpenClaw 是当前内置探测器，对应 `asset_type=openclaw`。

## 目录结构

- `prober/`：Go 探测工程，包含 detector 注册表、`assetprobe` 平台入口、`ocprobe` 兼容入口和 OpenClaw 指纹库。
- `src/agentsectool_scanner/`：平台主流程 Python 包，包括发现、入库、看板、进度队列和 GeoIP 富化。
- `tools/`：外部测绘源采集与一次性工具，包括 FOFA、ClawSec、scope、fingerprint、scan_test。
- `config/`：跨模块配置模板。
- `docs/`：项目文档与历史归档。

默认运行数据按生产者就近存放：

- scanner 权威库：`src/agentsectool_scanner/store/data/scan_results.sqlite`
- discovery 候选：`src/agentsectool_scanner/discovery/output/candidates.csv`
- assetprobe 结果：`prober/output/results.jsonl`
- FOFA 库与导出：`tools/fofa/data/fofa.sqlite`、`tools/fofa/output/candidates.csv`
- ClawSec 库：`tools/clawsec/data/clawsec.sqlite`
- OpenClaw 指纹库：`prober/fingerprints/openclaw.json`

## 快速验证

本地测试不向公网发包：

```bash
make test
make demo
```

`make demo` 会执行：

```text
agentsectool_scanner.discovery(localhost) -> assetprobe --type openclaw -> agentsectool_scanner.store -> stats
```

如需手动跑最小链路：

```bash
export PYTHONPATH=src:.
python3 -m agentsectool_scanner.discovery --cidr 127.0.0.0/30 --ports 18789 --backend internal --allow-reserved
prober/bin/assetprobe --type openclaw --fingerprints prober/fingerprints/openclaw.json \
  -o prober/output/results.jsonl src/agentsectool_scanner/discovery/output/candidates.csv
python3 -m agentsectool_scanner.store --in prober/output/results.jsonl --stats
python3 -m agentsectool_scanner.dashboard
```

看板默认地址：`http://127.0.0.1:8787/`。

## 探测入口

推荐入口是 `assetprobe`：

```bash
go -C prober build -o bin/assetprobe ./cmd/assetprobe
prober/bin/assetprobe --list-types
prober/bin/assetprobe --type openclaw --fingerprints prober/fingerprints/openclaw.json \
  -o prober/output/results.jsonl src/agentsectool_scanner/discovery/output/candidates.csv
```

目标可为精确 IPv4、CIDR、通配 IPv4、文件路径或 `-` 标准输入。候选 CSV 会按第一列取 IP。

兼容入口 `ocprobe` 仍可用于 OpenClaw：

```bash
go -C prober build -o bin/ocprobe ./cmd/ocprobe
prober/bin/ocprobe --fingerprints prober/fingerprints/openclaw.json \
  -o prober/output/results.jsonl targets.txt
```

ZGrab2 OpenClaw 模块仍保留：

```bash
make zgrab
echo "1.2.3.4" | prober/bin/zgrab-openclaw openclaw --port 18789 \
  --blocklist-file=config/blocklist.txt --fingerprints prober/fingerprints/openclaw.json
```

## 扩展新资产类型

新增资产类型时只需要走四个落点：

1. 在 `prober/detectors/<type>/` 实现 detector，并通过 `detectors.Register()` 注册。
2. 输出平台字段：`asset_type`、`detector`、`ip`、`port`、`is_match`、`category`、`matched`、`error_type`、`ts`。
3. 如有版本或专用证据，继续写入 detector 自己的 JSON 字段。
4. 如需人读报告，为该资产类型补充报告渲染逻辑。

`category` 统一含义：

- `confirmed`：确认目标资产，且拿到版本或版本候选。
- `confirmed_no_version`：确认目标资产，但版本未知。
- `suspect`：命中特征但未达确认白名单，保留复扫或优化。

## 被动测绘源

FOFA 只给候选，项目自己的探测器负责最终确认与版本测定：

```bash
export PYTHONPATH=src:.
FOFA_EMAIL=... FOFA_KEY=... python3 -m tools.fofa info
python3 -m tools.fofa pull --full --before 2026-05-30
python3 -m tools.fofa export --limit 500
prober/bin/assetprobe --type openclaw --fingerprints prober/fingerprints/openclaw.json \
  -o prober/output/results.jsonl tools/fofa/output/candidates.csv
make load
```

ClawSec 是 OpenClaw 暴露面被动源，免凭据，按每日快照入库：

```bash
export PYTHONPATH=src:.
python3 -m tools.clawsec info
python3 -m tools.clawsec pull
python3 -m tools.clawsec longlived --min-days 3
python3 -m tools.clawsec overlap
```

第三方平台的版本标注只作为外部参考；本项目认可的确认结果以 `assetprobe` 实时探测结果为准。

## 主动扫描边界

主动扫描会对目标 IP 发起真实连接。大规模扫描必须具备授权、黑名单、限速、可识别出口和 abuse 联系方式，不应从开发笔记本直接扫任意公网地址段。

```bash
export PYTHONPATH=src:.
cp config/blocklist.example.txt config/blocklist.txt
sudo env PYTHONPATH=src:. python3 -m agentsectool_scanner.discovery --cidr 0.0.0.0/0 --backend masscan --rate 20000 \
  --excludefile config/blocklist.txt
prober/bin/assetprobe --type openclaw --fingerprints prober/fingerprints/openclaw.json \
  -o prober/output/results.jsonl src/agentsectool_scanner/discovery/output/candidates.csv
python3 -m agentsectool_scanner.store --in prober/output/results.jsonl --stats
```

## 安全约束

- 探测器默认只读，不发送改状态请求或配置写入请求。
- 凭据必须走环境变量或 gitignore 中的本地配置。
- JSONL、SQLite 和 probe_records 可能包含目标响应原文，按敏感运行数据处理。
- 全网执行属于运营动作，必须有授权范围与合规前置。
