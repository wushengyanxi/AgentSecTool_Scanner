"""Repository-local default paths used by Python CLIs."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = ROOT / "src" / "agentsectool_scanner"
TOOLS_ROOT = ROOT / "tools"
PROBER_ROOT = ROOT / "prober"

SCANNER_DB = SRC_ROOT / "store" / "data" / "scan_results.sqlite"
DISCOVERY_CANDIDATES = SRC_ROOT / "discovery" / "output" / "candidates.csv"
PROBER_RESULTS = PROBER_ROOT / "output" / "results.jsonl"
OPENCLAW_FINGERPRINTS = PROBER_ROOT / "fingerprints" / "openclaw.json"

FOFA_DB = TOOLS_ROOT / "fofa" / "data" / "fofa.sqlite"
FOFA_CANDIDATES = TOOLS_ROOT / "fofa" / "output" / "candidates.csv"
CLAWSEC_DB = TOOLS_ROOT / "clawsec" / "data" / "clawsec.sqlite"
SCOPE_CN_CIDRS = TOOLS_ROOT / "scope" / "output" / "cn-cidrs.txt"

GEOIP_CONFIG = SRC_ROOT / "geoip" / "geoip.ini"
GEOIP_CITY_DB = SRC_ROOT / "geoip" / "data" / "GeoLite2-City.mmdb"
