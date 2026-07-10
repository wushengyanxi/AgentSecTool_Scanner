package main

import "github.com/wushengyanxi/agentsectool-scanner/prober/targeting"

// ExpandTarget keeps the legacy ocprobe tests and package API intact while the
// target expansion implementation lives in the platform-level targeting package.
func ExpandTarget(expr string, emit func(ip string) error) error {
	return targeting.ExpandTarget(expr, emit)
}
