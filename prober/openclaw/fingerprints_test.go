package openclaw

import (
	"strings"
	"testing"
)

func TestMatchImplicit(t *testing.T) {
	db := &FingerprintDB{Entries: []FingerprintEntry{{
		Version:     "2026.5.17",
		AssetHashes: []string{"index-DC4lnoz-.js", "index-B6U1kUNL.css"},
		CSPSHA256:   "43d24669088164c2c369e198a238acf99f8ef2fd571fc30ad1e020df6e71672b",
	}}}

	// 资产哈希集合匹配（顺序无关），唯一命中。
	if h := db.MatchImplicit(Evidence{AssetHashes: []string{"index-B6U1kUNL.css", "index-DC4lnoz-.js"}}); len(h) != 1 || h[0] != "2026.5.17" {
		t.Fatalf("asset-set match: got %v want [2026.5.17]", h)
	}
	// 仅有 CSP、资产名拿不到 → 返回空（不再退到 CSP 匹配，因 CSP 全版本相同、区分力为零）。
	if h := db.MatchImplicit(Evidence{CSPSHA256: "43d24669088164c2c369e198a238acf99f8ef2fd571fc30ad1e020df6e71672b"}); h != nil {
		t.Fatalf("csp-only should not match (csp 无区分力): got %v", h)
	}
	// 不匹配则返回 nil。
	if h := db.MatchImplicit(Evidence{AssetHashes: []string{"index-zzz.js"}}); h != nil {
		t.Fatalf("expected no match, got %v", h)
	}
	// nil DB 安全。
	var nilDB *FingerprintDB
	if h := nilDB.MatchImplicit(Evidence{AssetHashes: []string{"index-DC4lnoz-.js"}}); h != nil {
		t.Fatalf("nil db should return nil, got %v", h)
	}
}

// TestMatchImplicitRange：两个版本资产指纹相同（纯后端改动、前端不变，如实测的 2026.3.7=2026.3.8），
// 应返回全部候选，由 determineVersion 标为 implicit-range，而非谎报单一精确版本。
func TestMatchImplicitRange(t *testing.T) {
	assets := []string{"index-shared.js", "index-shared.css"}
	db := &FingerprintDB{Entries: []FingerprintEntry{
		{Version: "2026.3.7", AssetHashes: assets},
		{Version: "2026.3.8", AssetHashes: assets},
	}}

	hits := db.MatchImplicit(Evidence{AssetHashes: []string{"index-shared.css", "index-shared.js"}})
	if len(hits) != 2 {
		t.Fatalf("range match: got %v want 2 candidates", hits)
	}

	ver, src, cand := determineVersion(Evidence{AssetHashes: assets}, db)
	if src != "implicit-range" {
		t.Fatalf("version_source: got %q want implicit-range", src)
	}
	if ver != "2026.3.7" {
		t.Fatalf("representative version: got %q want 2026.3.7", ver)
	}
	if strings.Join(cand, ",") != "2026.3.7,2026.3.8" {
		t.Fatalf("candidates: got %v want [2026.3.7 2026.3.8]", cand)
	}
}
