package openclaw

import (
	"encoding/json"
	"os"
)

// FingerprintDB 把"可观测签名 → 版本"。由 harness/build_corpus.py 逐版本起容器记录签名而成。
type FingerprintDB struct {
	Entries []FingerprintEntry `json:"entries"`
}

// FingerprintEntry 是某一版本的外部可观测签名。
type FingerprintEntry struct {
	Version     string   `json:"version"`
	AssetHashes []string `json:"asset_hashes,omitempty"`
	CSPSHA256   string   `json:"csp_sha256,omitempty"`
	FaviconMD5  string   `json:"favicon_md5,omitempty"`
}

// LoadFingerprintDB 从 JSON 文件载入指纹库。
func LoadFingerprintDB(path string) (*FingerprintDB, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var db FingerprintDB
	if err := json.Unmarshal(b, &db); err != nil {
		return nil, err
	}
	return &db, nil
}

// MatchImplicit 用隐式信号反推版本：首页资产哈希集合精确匹配优先，CSP 哈希次之。
// 资产名随每次构建的内容哈希变化，因此集合精确匹配能定位到具体版本。
func (db *FingerprintDB) MatchImplicit(ev Evidence) string {
	if db == nil {
		return ""
	}
	evAssets := toSet(ev.AssetHashes)
	if len(evAssets) > 0 {
		for _, e := range db.Entries {
			if len(e.AssetHashes) > 0 && setsEqual(toSet(e.AssetHashes), evAssets) {
				return e.Version
			}
		}
	}
	if ev.CSPSHA256 != "" {
		for _, e := range db.Entries {
			if e.CSPSHA256 != "" && e.CSPSHA256 == ev.CSPSHA256 {
				return e.Version
			}
		}
	}
	return ""
}

func toSet(xs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		m[x] = struct{}{}
	}
	return m
}

func setsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}
