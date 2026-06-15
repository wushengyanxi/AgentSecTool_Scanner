package openclaw

import "strings"

// determineVersion 取版本：优先直读 serverVersion（疏防实例），否则隐式反推（需指纹库）。
// 返回 (version, source, candidates)：
//   - 直读命中：version=精确版本，source="direct"，candidates=nil
//   - 隐式命中唯一：version=该版本，source="implicit"，candidates=nil
//   - 隐式命中多个（资产指纹相同的不可区分区间）：version=区间内代表版本，
//     source="implicit-range"，candidates=全部候选（如 ["2026.3.7","2026.3.8"]）
//   - 未命中：全空
func determineVersion(ev Evidence, fp *FingerprintDB) (version, source string, candidates []string) {
	if ev.ServerVersion != "" {
		return normalizeVersion(ev.ServerVersion), "direct", nil
	}
	if fp != nil {
		if hits := fp.MatchImplicit(ev); len(hits) == 1 {
			return hits[0], "implicit", nil
		} else if len(hits) > 1 {
			return hits[0], "implicit-range", hits
		}
	}
	return "", "", nil
}

// normalizeVersion 去掉前导 v（OpenClaw 运行时版本可能形如 v2026.5.17）。
func normalizeVersion(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}
