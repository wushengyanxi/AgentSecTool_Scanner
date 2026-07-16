FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

COPY --from=ghcr.io/astral-sh/uv:0.11.17@sha256:03bdc89bb9798628846e60c3a9ad19006c8c3c724ccd2985a33145c039a0577b /uv /uvx /bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/scanner \
    CODEX_HOME=/home/scanner/.codex \
    PYTHONPATH=/opt/agentsectool-scanner/src \
    PATH=/opt/agentsectool-scanner/.venv/bin:$PATH

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl dnsutils nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/agentsectool-scanner
COPY src/agentsectool_scanner/agent_runtime/requirements.lock ./requirements.lock
RUN uv venv .venv \
    && uv pip install --python .venv/bin/python --requirement requirements.lock

COPY src/agentsectool_scanner/__init__.py ./src/agentsectool_scanner/__init__.py
COPY src/agentsectool_scanner/paths.py ./src/agentsectool_scanner/paths.py
COPY src/agentsectool_scanner/agent_runtime ./src/agentsectool_scanner/agent_runtime

RUN useradd --create-home --uid 10001 --shell /bin/bash scanner \
    && mkdir -p /home/scanner/.codex /workspace /workspace/runs \
    && chown -R scanner:scanner /home/scanner /workspace

USER scanner
WORKDIR /workspace
ENTRYPOINT ["python", "-m", "agentsectool_scanner.agent_runtime.worker"]
