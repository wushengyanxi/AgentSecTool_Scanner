package openclaw

import (
	"context"

	"github.com/wushengyanxi/agentsectool-scanner/prober/detectors"
	oc "github.com/wushengyanxi/agentsectool-scanner/prober/openclaw"
)

const AssetType = "openclaw"

type Detector struct {
	fingerprints *oc.FingerprintDB
}

func init() {
	detectors.Register(AssetType, New)
}

func New(cfg detectors.Config) (detectors.Detector, error) {
	var fpdb *oc.FingerprintDB
	if cfg.FingerprintsPath != "" {
		db, err := oc.LoadFingerprintDB(cfg.FingerprintsPath)
		if err != nil {
			return nil, err
		}
		fpdb = db
	}
	return &Detector{fingerprints: fpdb}, nil
}

func (d *Detector) Type() string { return AssetType }

func (d *Detector) Name() string { return "OpenClaw gateway detector" }

func (d *Detector) DefaultPorts() []uint16 { return []uint16{oc.DefaultPort} }

func (d *Detector) Probe(ctx context.Context, target detectors.Target, opts detectors.ProbeOptions) (any, error) {
	res := oc.Probe(ctx, target.Host, target.Port, oc.Options{
		TLS:          target.TLS,
		Timeout:      opts.Timeout,
		Fingerprints: d.fingerprints,
	})
	return res, nil
}
