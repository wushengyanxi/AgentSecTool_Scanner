package openclaw

import "strings"

// determineVersion 取版本：优先直读 serverVersion（疏防实例），否则隐式反推（需指纹库）。
func determineVersion(ev Evidence, fp *FingerprintDB) (version, source string) {
	if ev.ServerVersion != "" {
		return normalizeVersion(ev.ServerVersion), "direct"
	}
	if fp != nil {
		if v := fp.MatchImplicit(ev); v != "" {
			return v, "implicit"
		}
	}
	return "", ""
}

// normalizeVersion 去掉前导 v（OpenClaw 运行时版本可能形如 v2026.5.17）。
func normalizeVersion(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}
