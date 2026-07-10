package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/wushengyanxi/agentsectool-scanner/prober/config"
)

type runConfig struct {
	rate         int64
	timeoutPerIP time.Duration
	concurrency  int64
	deadline     time.Duration
	ports        []uint16
	verbose      int64
}

func builtinConfig() runConfig {
	return runConfig{
		rate:         50,
		timeoutPerIP: 8 * time.Second,
		concurrency:  16,
		deadline:     0,
		ports:        nil,
		verbose:      0,
	}
}

func loadConfig() runConfig {
	c := builtinConfig()
	data, ok := readConfigFile()
	if !ok {
		return c
	}
	cfg, err := config.Parse(data)
	if err != nil {
		return c
	}
	c.rate = cfg.GetInt("probe", "rate", c.rate)
	c.concurrency = cfg.GetInt("probe", "concurrency", c.concurrency)
	c.timeoutPerIP = parseDur(cfg.GetString("probe", "timeout_per_ip", ""), c.timeoutPerIP)
	c.deadline = parseDur(cfg.GetString("scan", "deadline", ""), c.deadline)
	c.verbose = cfg.GetInt("output", "verbose", c.verbose)
	if ps := cfg.GetIntSlice("scan", "ports", nil); len(ps) > 0 {
		c.ports = c.ports[:0]
		for _, p := range ps {
			if p > 0 && p <= 65535 {
				c.ports = append(c.ports, uint16(p))
			}
		}
	}
	return c
}

func parseDur(s string, def time.Duration) time.Duration {
	if s == "" || s == "0" {
		return def
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return def
}

func readConfigFile() ([]byte, bool) {
	candidates := []string{"config.toml"}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates,
			filepath.Join(filepath.Dir(exe), "config.toml"),
			filepath.Join(filepath.Dir(exe), "..", "config.toml"),
		)
	}
	candidates = append(candidates, "prober/config.toml")
	for _, p := range candidates {
		if data, err := os.ReadFile(p); err == nil {
			return data, true
		}
	}
	return nil, false
}
