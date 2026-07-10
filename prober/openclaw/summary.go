package openclaw

import "github.com/wushengyanxi/agentsectool-scanner/prober/detectors"

const (
	AssetType = "openclaw"
	Detector  = "openclaw"
)

func categoryFor(verdict bool, version string, candidates []string, matched []string) string {
	if verdict {
		if version != "" || len(candidates) > 0 {
			return "confirmed"
		}
		return "confirmed_no_version"
	}
	if len(matched) > 0 {
		return "suspect"
	}
	return ""
}

func (r Result) DetectorSummary() detectors.Summary {
	assetType := r.AssetType
	if assetType == "" {
		assetType = AssetType
	}
	det := r.Detector
	if det == "" {
		det = Detector
	}
	return detectors.Summary{
		AssetType: assetType,
		Detector:  det,
		IP:        r.IP,
		Port:      r.Port,
		IsMatch:   r.IsMatch,
		Category:  r.Category,
		Version:   r.Version,
		Matched:   r.Matched,
		ErrorType: r.ErrorType,
	}
}
