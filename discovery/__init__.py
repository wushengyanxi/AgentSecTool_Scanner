"""发现层：主动扫描（masscan/ZMap，任意 CIDR 直至全网）+ FOFA 被动种子，
合并去重并剔除黑名单后产出 candidates.csv（IP,port），喂给探测器。

仅用标准库，可 `python3 -m discovery ...` 直接运行。
"""
