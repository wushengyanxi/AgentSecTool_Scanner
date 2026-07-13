"""Auxiliary collectors and one-off tools for AgentSecTool Scanner."""

from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parent.parent
_SRC = str(_ROOT / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
