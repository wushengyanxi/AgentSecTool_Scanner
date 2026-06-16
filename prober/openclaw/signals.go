package openclaw

// evaluate 做二元研判（is OpenClaw / not），不使用概率分值。
//
// 测试项按可伪造性分级（确证/强/弱），由一个明确的证据组合白名单判定（详见
// docs/扫描器优化与研判机制.html §04）：
//
//	True 当且仅当满足任一，其余一切组合 = False：
//	  C1: T1                       // 确证级单独成立（control-ui 自报版本，伪造=真实现）
//	  C2: T2 && (T3 || T4)         // WS 强证据 + HTTP 路由面强证据，跨表面双强
//
// 纯弱证据（T5/T6/T7）无论命中多少都不参与达标，只在 matched 里列出供报告说明。
//
// 返回 (verdict, matched, rule)：matched 是命中的测试项编号集合（含弱证据，按 T1..T7 顺序），
// rule 是触发的白名单条件（"C1"/"C2"），verdict=false 时 rule 为空。
func evaluate(ev Evidence) (verdict bool, matched []string, rule string) {
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

	// 白名单：确证级优先，其次跨表面双强。
	switch {
	case t1:
		return true, matched, "C1"
	case t2 && (t3 || t4):
		return true, matched, "C2"
	default:
		return false, matched, ""
	}
}
