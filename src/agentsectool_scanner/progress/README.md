# progress 模块说明

`progress` 负责维护大范围扫描的块级进度。它把 CIDR 范围切成固定前缀的扫描块，记录每个块在一个 campaign 中的领取与完成状态，便于多 worker 协同扫描和断点续扫。

## 数据表

模块使用 scanner 库中的 `scan_blocks` 表：

- `campaign`：扫描轮次名称。
- `block_cidr`：被分配的 CIDR 块。
- `status`：`pending`、`in_progress`、`done`。
- `worker`：领取该块的 worker 名称。
- `claimed_at`：领取时间戳。
- `done_at`：完成时间戳。

表结构由 `agentsectool_scanner.progress.blocks` 在访问数据库时创建，默认数据库为 `src/agentsectool_scanner/store/data/scan_results.sqlite`。

## CLI

登记一个扫描轮次：

```bash
python3 -m agentsectool_scanner.progress seed --campaign cn-2026w24 --cidrs tools/scope/output/cn-cidrs.txt --prefix 16
```

查看进度：

```bash
python3 -m agentsectool_scanner.progress status --campaign cn-2026w24
```

领取一个待扫块：

```bash
python3 -m agentsectool_scanner.progress claim --campaign cn-2026w24 --worker worker-a
```

`claim` 使用 SQLite 的 `BEGIN IMMEDIATE` 串行化领取过程，避免多个 worker 拿到同一个块。

## 当前边界

`progress` 只负责扫描块的登记、领取和状态统计；它不直接调用 `assetprobe`，也不负责把领取到的块自动标记为完成。`mark_done` 与 `reset_stale` 已在 `progress.blocks` 中实现并有测试覆盖，但当前没有独立 CLI 子命令。

实际扫描流程需要外部调度器或脚本完成：

1. 调用 `python3 -m agentsectool_scanner.progress claim` 领取块。
2. 用 `assetprobe --type <asset_type>` 或其他扫描入口处理该块。
3. 扫描成功后调用 `progress.blocks.mark_done` 或后续补充的 CLI 标记完成。

## 验证

相关单测位于 `src/agentsectool_scanner/progress/tests/test_blocks.py`，覆盖 CIDR 切块、幂等登记、领取、完成和过期重置。
