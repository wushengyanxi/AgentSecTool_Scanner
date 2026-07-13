"""落地层：results.jsonl → SQLite（assets 资产登记 + observations 时序观测）。

按内容指纹（favicon + 资产哈希 + CSP）给资产去重，使同一实例换 IP 仍归一条资产；
拿不到内容指纹时退回 ip:port。仅用标准库（sqlite3），跑在本地宿主机。
"""
