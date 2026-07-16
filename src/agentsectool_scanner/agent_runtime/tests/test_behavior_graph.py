from __future__ import annotations

from pathlib import Path

from agentsectool_scanner.agent_runtime.render import render_behavior_graph_html
from agentsectool_scanner.agent_runtime.trace import TraceSink, read_trace


def test_behavior_graph_renders_codex_tool_name(tmp_path: Path) -> None:
    sink = TraceSink(run_id="graph-run", task_id="task", trace_dir=tmp_path)
    root = sink.emit(stage="P0", type="task_input", payload={"raw_text": "inspect"})
    parsed = sink.emit(
        stage="core",
        type="parsed_tool_call",
        parents=[root.id],
        payload={"call_id": "item-1", "tool_name": "shell", "arguments": {}},
    )
    sink.emit(
        stage="core",
        type="tool_result",
        parents=[parsed.id],
        payload={"call_id": "item-1", "result": {"exitCode": 0}},
    )

    html = render_behavior_graph_html(read_trace(run_id="graph-run", trace_dir=tmp_path))

    assert "shell · item-1" in html
    assert html.count('class="edge"') == 2
