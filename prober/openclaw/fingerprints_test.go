package openclaw

import "testing"

func TestMatchImplicit(t *testing.T) {
	db := &FingerprintDB{Entries: []FingerprintEntry{{
		Version:     "2026.5.17",
		AssetHashes: []string{"index-DC4lnoz-.js", "index-B6U1kUNL.css"},
		CSPSHA256:   "43d24669088164c2c369e198a238acf99f8ef2fd571fc30ad1e020df6e71672b",
	}}}

	// 资产哈希集合匹配（顺序无关）。
	if v := db.MatchImplicit(Evidence{AssetHashes: []string{"index-B6U1kUNL.css", "index-DC4lnoz-.js"}}); v != "2026.5.17" {
		t.Fatalf("asset-set match: got %q want 2026.5.17", v)
	}
	// 仅 CSP 哈希匹配（资产拿不到时的退路）。
	if v := db.MatchImplicit(Evidence{CSPSHA256: "43d24669088164c2c369e198a238acf99f8ef2fd571fc30ad1e020df6e71672b"}); v != "2026.5.17" {
		t.Fatalf("csp match: got %q want 2026.5.17", v)
	}
	// 不匹配则返回空。
	if v := db.MatchImplicit(Evidence{AssetHashes: []string{"index-zzz.js"}}); v != "" {
		t.Fatalf("expected no match, got %q", v)
	}
	// nil DB 安全。
	var nilDB *FingerprintDB
	if v := nilDB.MatchImplicit(Evidence{AssetHashes: []string{"index-DC4lnoz-.js"}}); v != "" {
		t.Fatalf("nil db should return empty, got %q", v)
	}
}
