package openclaw

import (
	"encoding/json"
	"os"
)

// FingerprintDB 把"可观测签名 → 版本"。由 fingerprint/build_corpus.py 逐版本起容器记录签名而成。
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

// MatchImplicit 用隐式信号反推版本：首页资产哈希集合精确匹配。
// 资产名随每次构建的内容哈希变化，但纯后端改动的相邻版本前端 bundle 不变、资产指纹相同
// （实测有若干组，如 2026.3.7=2026.3.8）。故返回【全部】匹配版本：单个=精确，多个=不可区分区间，
// 由调用方如实呈现，不谎报单一精确版本。资产名不在库（如未采集的新版本）则返回 nil（无版本）。
//
// 注意：不再用 CSP 哈希回退——control-ui 那串 CSP 是静态常量、全版本相同（区分力为零），
// 用它匹配会命中指纹库的全部版本，产出一个毫无意义的「全版本区间」。资产名不命中就老实报无版本。
func (db *FingerprintDB) MatchImplicit(ev Evidence) []string {
	if db == nil {
		return nil
	}
	evAssets := toSet(ev.AssetHashes)
	if len(evAssets) == 0 {
		return nil
	}
	var hits []string
	for _, e := range db.Entries {
		if len(e.AssetHashes) > 0 && setsEqual(toSet(e.AssetHashes), evAssets) {
			hits = append(hits, e.Version)
		}
	}
	return hits
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
