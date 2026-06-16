"""基于 ClawSec 测绘平台的 OpenClaw 暴露面发现工作流（与 fofa/ 平级的被动源）。

ClawSec（clawsec.tcode.com.cn）是高校做的 OpenClaw 公网暴露测绘平台，公开、频繁更新。
无需凭据；IP 隐藏一位（补全/枚举由下游探测处理）；携带平台自己的版本判定与历史漏洞标注。
每日全量快照入 data/clawsec/clawsec.sqlite 的 clawsec_snapshots 表（带 snapshot_date，同实例每天一行），
跨快照可分析长期有效实例；与 fofa 库跨库 ATTACH 可交叉。
平台只给候选与它的判定；确认 + 取版本由本项目探测器完成，可与平台版本做双源对比。
"""
