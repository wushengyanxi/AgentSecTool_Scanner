package openclaw

// evaluate 做二元研判（is OpenClaw / not），不使用概率分值。
//
// 测试项按可仿冒难度分级（确证/强/弱），由一个明确的证据组合白名单判定（详见
// docs/扫描器优化与研判机制.html §04）：
//
//	True 当且仅当满足任一，其余一切组合 = False：
//	  C1: T1                       // 确证级单独成立（control-ui 自报版本，仿冒成本=真实现）
//	  C2: T2 && (T3 || T4)         // WS 强证据 × HTTP 路由面强证据，跨表面双强
//	  C3: T2 && assetHashMatch     // WS 强证据 × 首页资产指纹精确命中指纹库，跨表面双强
//
// assetHashMatch 表示首页抽到的 assets/index-<hash>.js|css 名集合与指纹库某版本条目
// 精确相等（setsEqual），由调用方用 FingerprintDB.MatchImplicit 预先算好传入。
// C3 覆盖的是这样一类实例：control-ui-config 未暴露 serverVersion（取决于部署配置，
// 故 T1 不命中）、又非 401（T3 不命中）、/healthz 也未命中（T4 不命中），但它确实是
// 某个已知版本的 OpenClaw —— 其前端构建产物的内容哈希逐一匹配到指纹库。资产指纹是
// HTTP 静态构建产物面，与 T2 的 WS 协议面正交：单独的资产指纹可被静态克隆首页伪造，
// 但叠加 T2（须真跑一个连上即推 connect.challenge 帧的服务端）后构成跨表面双强，
// 抗仿冒性不低于 C2。故资产指纹单独不达标，必须与 T2 联合。
//
// 纯弱证据（T5/T6/T7）无论命中多少都不参与达标，只在 matched 里列出供报告说明。
//
// 返回 (verdict, matched, rule)：matched 是命中的测试项编号集合（含弱证据，按 T1..T7 顺序），
// rule 是触发的白名单条件（"C1"/"C2"/"C3"），verdict=false 时 rule 为空。
func evaluate(ev Evidence, assetHashMatch bool) (verdict bool, matched []string, rule string) {
	t1 := ev.ControlUIStatus == 200 && ev.ServerVersion != ""
	t2 := ev.WSChallenge
	t3 := ev.ControlUIStatus == 401
	t4 := ev.HealthzMatch
	t5 := ev.FaviconMD5 == FaviconMD5
	t6 := ev.Title == TitleMarker
	t7 := ev.HeaderTriplet

	// matched 按 T1..T7 顺序收集，便于报告与复查。
	for _, m := range []struct {
		hit bool
		id  string
	}{{t1, T1}, {t2, T2}, {t3, T3}, {t4, T4}, {t5, T5}, {t6, T6}, {t7, T7}} {
		if m.hit {
			matched = append(matched, m.id)
		}
	}

	// 白名单：确证级优先，其次两条跨表面双强。
	switch {
	case t1:
		return true, matched, "C1"
	case t2 && (t3 || t4):
		return true, matched, "C2"
	case t2 && assetHashMatch:
		return true, matched, "C3"
	default:
		return false, matched, ""
	}
}
