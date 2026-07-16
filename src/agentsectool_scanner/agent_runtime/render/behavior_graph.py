from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from html import escape
from pathlib import Path

from agentsectool_scanner.agent_runtime.trace import TraceEvent, read_trace

_MARGIN_X = 48.0
_MARGIN_Y = 56.0
_NODE_WIDTH = 190.0
_NODE_HEIGHT = 76.0
_COL_GAP = 58.0
_ROW_GAP = 100.0


@dataclass(frozen=True)
class GraphNode:
    """行为图中的一个事件节点。"""

    event: TraceEvent
    depth: int
    x: float
    y: float


@dataclass(frozen=True)
class GraphEdge:
    """行为图中的一条因果边。"""

    parent_id: str
    child_id: str


@dataclass(frozen=True)
class BehaviorGraph:
    """已完成分层布局的行为图。"""

    nodes: list[GraphNode]
    edges: list[GraphEdge]
    width: float
    height: float


def build_behavior_graph(events: Sequence[TraceEvent]) -> BehaviorGraph:
    """从 trace 事件构建分层行为图。

    :param events: 按 trace 顺序读取出的事件。
    :return: 带坐标的行为图。
    :raises ValueError: 当 trace 为空、parent 缺失或存在环时抛出。
    """

    if not events:
        raise ValueError("trace must contain at least one event")

    ordered_events = sorted(events, key=lambda event: event.seq)
    event_by_id = {event.id: event for event in ordered_events}
    if len(event_by_id) != len(ordered_events):
        raise ValueError("trace contains duplicate event ids")

    depth_by_id: dict[str, int] = {}
    for event in ordered_events:
        _event_depth(event.id, event_by_id, depth_by_id, visiting=set())

    layers: dict[int, list[TraceEvent]] = defaultdict(list)
    for event in ordered_events:
        layers[depth_by_id[event.id]].append(event)

    max_layer_size = max(len(layer) for layer in layers.values())
    inner_width = max_layer_size * _NODE_WIDTH + max(max_layer_size - 1, 0) * _COL_GAP
    width = inner_width + (_MARGIN_X * 2)
    max_depth = max(layers)
    height = _MARGIN_Y * 2 + (max_depth + 1) * _NODE_HEIGHT + max_depth * _ROW_GAP

    nodes: list[GraphNode] = []
    for depth in sorted(layers):
        layer = sorted(layers[depth], key=lambda event: event.seq)
        row_width = len(layer) * _NODE_WIDTH + max(len(layer) - 1, 0) * _COL_GAP
        x = _MARGIN_X + ((inner_width - row_width) / 2)
        y = _MARGIN_Y + depth * (_NODE_HEIGHT + _ROW_GAP)
        for event in layer:
            nodes.append(GraphNode(event=event, depth=depth, x=x, y=y))
            x += _NODE_WIDTH + _COL_GAP

    edges = [
        GraphEdge(parent_id=parent_id, child_id=event.id)
        for event in ordered_events
        for parent_id in event.parents
    ]
    return BehaviorGraph(nodes=nodes, edges=edges, width=width, height=height)


def render_behavior_graph_html(
    events: Sequence[TraceEvent],
    *,
    title: str | None = None,
) -> str:
    """把 trace 事件渲染成自包含 HTML。

    :param events: 按 trace 顺序读取出的事件。
    :param title: 页面标题；未提供时使用 trace run_id。
    :return: 包含内联 SVG 的完整 HTML 字符串。
    """

    graph = build_behavior_graph(events)
    run_id = events[0].run_id
    page_title = title or f"Behavior Graph · {run_id}"
    return _html_document(graph, page_title=page_title, run_id=run_id)


def write_behavior_graph_html(
    *,
    run_id: str,
    trace_dir: str | Path,
    output_path: str | Path,
) -> Path:
    """读取指定 trace 并把行为图 HTML 写入磁盘。

    :param run_id: 要渲染的运行标识。
    :param trace_dir: trace JSONL 所在目录。
    :param output_path: HTML 输出路径。
    :return: 写入后的输出路径。
    """

    events = read_trace(run_id=run_id, trace_dir=trace_dir)
    html = render_behavior_graph_html(events)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path


def _event_depth(
    event_id: str,
    event_by_id: dict[str, TraceEvent],
    depth_by_id: dict[str, int],
    visiting: set[str],
) -> int:
    """递归计算单个事件的因果深度。"""

    if event_id in depth_by_id:
        return depth_by_id[event_id]
    if event_id in visiting:
        raise ValueError("trace parents contain a cycle")

    event = event_by_id.get(event_id)
    if event is None:
        raise ValueError(f"trace parent references missing event: {event_id}")

    visiting.add(event_id)
    if not event.parents:
        depth = 0
    else:
        depth = 1 + max(
            _event_depth(parent_id, event_by_id, depth_by_id, visiting)
            for parent_id in event.parents
        )
    visiting.remove(event_id)
    depth_by_id[event_id] = depth
    return depth


def _html_document(graph: BehaviorGraph, *, page_title: str, run_id: str) -> str:
    """生成完整 HTML 文档。"""

    node_by_id = {node.event.id: node for node in graph.nodes}
    edges = "\n".join(_edge_svg(edge, node_by_id) for edge in graph.edges)
    nodes = "\n".join(_node_svg(node) for node in graph.nodes)
    escaped_title = escape(page_title)
    escaped_run_id = escape(run_id)
    width = _fmt(graph.width)
    height = _fmt(graph.height)

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escaped_title}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f8fa;
      --ink: #1f2933;
      --muted: #687282;
      --line: #9aa6b2;
      --panel: #ffffff;
      --border: #d7dee8;
      --core: #e8f1ff;
      --p0: #e9f8ee;
      --p1: #fff2dd;
      --p2: #f1eafe;
      --exit-ok: #dff5e7;
      --exit-error: #ffe3e3;
      --exit-killed: #fff1c7;
    }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    header {{
      padding: 24px 28px 12px;
    }}
    h1 {{
      margin: 0 0 6px;
      font-size: 22px;
      font-weight: 650;
      letter-spacing: 0;
    }}
    .meta {{
      color: var(--muted);
      font-size: 13px;
    }}
    main {{
      padding: 0 24px 28px;
      overflow-x: auto;
    }}
    svg {{
      display: block;
      min-width: {width}px;
      background: var(--panel);
      border: 1px solid var(--border);
    }}
    .edge {{
      stroke: var(--line);
      stroke-width: 1.6;
      fill: none;
      marker-end: url(#arrow);
    }}
    .node rect {{
      fill: #f4f6f8;
      stroke: #9ba8b7;
      stroke-width: 1.2;
      rx: 7;
    }}
    .node text {{
      fill: var(--ink);
      text-anchor: middle;
      dominant-baseline: middle;
      font-size: 12px;
      letter-spacing: 0;
    }}
    .node .label {{
      font-weight: 650;
      font-size: 12.5px;
    }}
    .node .detail {{
      fill: var(--muted);
      font-size: 11.5px;
    }}
    .stage-P0 rect {{ fill: var(--p0); }}
    .stage-P1 rect {{ fill: var(--p1); }}
    .stage-P2 rect {{ fill: var(--p2); }}
    .stage-core rect {{ fill: var(--core); }}
    .outcome-ok rect {{ fill: var(--exit-ok); }}
    .outcome-error rect {{ fill: var(--exit-error); }}
    .outcome-killed rect {{ fill: var(--exit-killed); }}
  </style>
</head>
<body>
  <header>
    <h1>{escaped_title}</h1>
    <div class="meta">run_id: {escaped_run_id}</div>
  </header>
  <main>
    <svg
      width="{width}"
      height="{height}"
      viewBox="0 0 {width} {height}"
      role="img"
      aria-label="{escaped_title}"
    >
      <defs>
        <marker
          id="arrow"
          markerWidth="10"
          markerHeight="10"
          refX="8"
          refY="3"
          orient="auto"
          markerUnits="strokeWidth"
        >
          <path d="M0,0 L0,6 L8,3 z" fill="#9aa6b2"></path>
        </marker>
      </defs>
      <g class="edges">
{edges}
      </g>
      <g class="nodes">
{nodes}
      </g>
    </svg>
  </main>
</body>
</html>
"""


def _edge_svg(edge: GraphEdge, node_by_id: dict[str, GraphNode]) -> str:
    """生成单条因果边的 SVG。"""

    parent = node_by_id[edge.parent_id]
    child = node_by_id[edge.child_id]
    x1 = parent.x + (_NODE_WIDTH / 2)
    y1 = parent.y + _NODE_HEIGHT
    x2 = child.x + (_NODE_WIDTH / 2)
    y2 = child.y
    mid_y = y1 + ((y2 - y1) / 2)
    return (
        '        <path class="edge" '
        f'd="M {_fmt(x1)} {_fmt(y1)} C {_fmt(x1)} {_fmt(mid_y)}, '
        f'{_fmt(x2)} {_fmt(mid_y)}, {_fmt(x2)} {_fmt(y2)}"></path>'
    )


def _node_svg(node: GraphNode) -> str:
    """生成单个事件节点的 SVG。"""

    event = node.event
    classes = ["node", f"stage-{event.stage}"]
    if event.outcome is not None:
        classes.append(f"outcome-{event.outcome}")

    label = escape(f"#{event.seq} {event.type}")
    detail = escape(_event_detail(event))
    title = escape(_event_title(event))
    class_attr = " ".join(classes)
    x = _fmt(node.x)
    y = _fmt(node.y)
    label_y = _fmt(node.y + 30)
    detail_y = _fmt(node.y + 52)

    return f"""        <g class="{class_attr}">
          <title>{title}</title>
          <rect x="{x}" y="{y}" width="{_fmt(_NODE_WIDTH)}" height="{_fmt(_NODE_HEIGHT)}"></rect>
          <text class="label" x="{_fmt(node.x + (_NODE_WIDTH / 2))}" y="{label_y}">{label}</text>
          <text class="detail" x="{_fmt(node.x + (_NODE_WIDTH / 2))}" y="{detail_y}">{detail}</text>
        </g>"""


def _event_detail(event: TraceEvent) -> str:
    """为节点生成一行简短说明。"""

    if event.outcome is not None:
        reason = event.payload.get("reason")
        suffix = f" · {reason}" if isinstance(reason, str) else ""
        return _trim(f"{event.outcome}{suffix}")
    if event.type == "parsed_tool_call":
        name = event.payload.get("tool_name") or event.payload.get("name")
        call_id = event.payload.get("call_id")
        if isinstance(name, str) and isinstance(call_id, str):
            return _trim(f"{name} · {call_id}")
    if event.type == "tool_result":
        call_id = event.payload.get("call_id")
        if isinstance(call_id, str):
            return _trim(call_id)
    if event.type == "task_input":
        raw_text = event.payload.get("raw_text")
        if isinstance(raw_text, str):
            return _trim(raw_text)
    return event.stage


def _event_title(event: TraceEvent) -> str:
    """生成 SVG title，供浏览器悬停查看。"""

    parent_text = ", ".join(event.parents) if event.parents else "none"
    outcome = event.outcome or "none"
    return f"{event.id}\nseq: {event.seq}\ndepends on: {parent_text}\noutcome: {outcome}"


def _trim(value: str, *, limit: int = 28) -> str:
    """把节点说明限制到单行可读长度。"""

    text = " ".join(value.split())
    if len(text) <= limit:
        return text
    return f"{text[: limit - 1]}…"


def _fmt(value: float) -> str:
    """稳定格式化 SVG 坐标。"""

    return f"{value:.1f}".rstrip("0").rstrip(".")
