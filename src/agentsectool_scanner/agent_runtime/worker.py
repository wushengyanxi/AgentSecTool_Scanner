from __future__ import annotations

import os
import sys

from agentsectool_scanner.agent_runtime.runtime import main


def worker_entry() -> None:
    """Run the agent process inside the restricted runtime container."""

    default_repl = os.environ.get("AGENTSECTOOL_AGENT_DEFAULT_REPL") == "1"
    prog = os.environ.get("AGENTSECTOOL_AGENT_PROG", "scanner-agent")
    raise SystemExit(main(sys.argv[1:], default_repl=default_repl, prog=prog))


if __name__ == "__main__":
    worker_entry()
