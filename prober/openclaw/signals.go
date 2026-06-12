package openclaw

// score 按"跨表面组合"逻辑给出置信度与判定（论证见 §01）。
//
// 核心：置信度相乘只在不同协议表面之间近似成立。三个独立表面——
//   - WS 协议面：connect.challenge
//   - HTTP 静态面：favicon / 标题（彼此相关，取较大者）
//   - HTTP 路由/头面：/healthz 体、control-ui-config 路由、响应头三件套
//
// 判定 = "WS 挑战(强单证) 或 ≥2 个不同表面命中"。
func score(ev Evidence) (confidence float64, isOpenClaw bool, signals []string) {
	pWS := 0.0
	if ev.WSChallenge {
		pWS = 0.99
		signals = append(signals, "ws_challenge")
	}

	pStatic := 0.0
	if ev.FaviconMD5 == FaviconMD5 {
		pStatic = maxf(pStatic, 0.95)
		signals = append(signals, "favicon")
	}
	if ev.Title == TitleMarker {
		pStatic = maxf(pStatic, 0.90)
		signals = append(signals, "title")
	}

	pRoute := 0.0
	if ev.HealthzMatch {
		pRoute = maxf(pRoute, 0.85)
		signals = append(signals, "healthz")
	}
	switch {
	case ev.ControlUIStatus == 200 && ev.ServerVersion != "":
		pRoute = maxf(pRoute, 0.95)
		signals = append(signals, "control_ui_config_200")
	case ev.ControlUIStatus == 401:
		pRoute = maxf(pRoute, 0.90)
		signals = append(signals, "control_ui_config_401")
	}
	if ev.HeaderTriplet {
		pRoute = maxf(pRoute, 0.60)
		signals = append(signals, "header_triplet")
	}

	confidence = noisyOR(pWS, pStatic, pRoute)

	surfaces := 0
	for _, p := range []float64{pWS, pStatic, pRoute} {
		if p > 0 {
			surfaces++
		}
	}
	isOpenClaw = ev.WSChallenge || surfaces >= 2 || confidence >= 0.97
	return confidence, isOpenClaw, signals
}

// noisyOR 把多个独立表面的命中概率合成（1 - ∏(1-p)）。
func noisyOR(ps ...float64) float64 {
	q := 1.0
	for _, p := range ps {
		q *= 1 - p
	}
	return 1 - q
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
