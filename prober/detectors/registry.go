package detectors

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Target is the platform-level scan target handed to a detector.
type Target struct {
	Host string
	Port uint16
	TLS  bool
}

// Config configures a detector instance for a scan run.
type Config struct {
	FingerprintsPath string
}

// ProbeOptions are per-target runtime options shared by all detectors.
type ProbeOptions struct {
	Timeout time.Duration
}

// Summary is the detector-neutral result view used by runners and progress UI.
type Summary struct {
	AssetType string
	Detector  string
	IP        string
	Port      uint16
	IsMatch   bool
	Category  string
	Version   string
	Matched   []string
	ErrorType string
}

// Summarized is implemented by detector result types that can expose a
// platform-neutral summary without losing their detector-specific evidence.
type Summarized interface {
	DetectorSummary() Summary
}

// Detector probes one asset type.
type Detector interface {
	Type() string
	Name() string
	DefaultPorts() []uint16
	Probe(ctx context.Context, target Target, opts ProbeOptions) (any, error)
}

// Closer is implemented by detectors that own worker processes.
type Closer interface {
	Close() error
}

// Factory creates a configured detector instance.
type Factory func(Config) (Detector, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

// Register installs a detector factory. It panics on duplicate types because
// duplicate asset types would make CLI behavior ambiguous.
func Register(assetType string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if assetType == "" {
		panic("detectors: empty asset type")
	}
	if _, ok := factories[assetType]; ok {
		panic("detectors: duplicate asset type " + assetType)
	}
	factories[assetType] = f
}

// New creates a configured detector by asset type.
func New(assetType string, cfg Config) (Detector, error) {
	mu.RLock()
	f := factories[assetType]
	mu.RUnlock()
	if f == nil {
		return nil, fmt.Errorf("unknown asset type %q (available: %v)", assetType, Types())
	}
	return f(cfg)
}

// Types returns registered asset types in stable order.
func Types() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(factories))
	for t := range factories {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// SummaryOf extracts a platform-neutral summary from a detector-specific result.
func SummaryOf(v any) Summary {
	if s, ok := v.(Summarized); ok {
		return s.DetectorSummary()
	}
	return Summary{}
}
