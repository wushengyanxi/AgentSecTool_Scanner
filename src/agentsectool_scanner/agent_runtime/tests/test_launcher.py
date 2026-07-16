from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from agentsectool_scanner.agent_runtime import launcher


def test_launcher_keeps_secret_out_of_docker_arguments(
    tmp_path: Path, monkeypatch
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
active_model = "openai"
trace_dir = "runs"
workspace = "/workspace"

[models.openai]
provider = "openai"
model = "gpt-test"
base_url = "https://api.example.test/v1"
api_key = "local-secret"
""".strip(),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(launcher.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(launcher, "_project_root", lambda: tmp_path)
    monkeypatch.setattr(launcher, "_ensure_runtime_image", lambda _root: "image:test")
    monkeypatch.setattr(launcher.subprocess, "run", fake_run)

    result = launcher.main(["--config", str(config_path), "run", "hello"])

    assert result == 0
    command = captured["command"]
    env = captured["env"]
    assert "local-secret" not in " ".join(command)
    assert env["AGENTSECTOOL_MODEL_API_KEY"] == "local-secret"
    serialized = env["AGENTSECTOOL_AGENT_CONFIG_JSON"]
    assert "local-secret" not in serialized
    config_json = json.loads(serialized)
    assert config_json["models"]["openai"]["api_key"] == ""
    assert "--config" not in command
    assert "--read-only" in command
    assert "--cap-drop" in command
    assert "ALL" in command
    assert "--cap-add" in command
    assert "NET_RAW" in command
    assert "no-new-privileges" in command
    assert any("uid=10001,gid=10001,mode=0700" in value for value in command)
    assert "/var/run/docker.sock" not in " ".join(command)


def test_trace_mount_preserves_absolute_paths(tmp_path: Path) -> None:
    absolute = tmp_path / "custom-runs"

    host, container = launcher._trace_mount(tmp_path, str(absolute))

    assert host == absolute
    assert container == "/workspace/runs"


def test_loopback_model_url_is_mapped_to_host_gateway() -> None:
    assert (
        launcher._container_base_url("http://127.0.0.1:4000/v1")
        == "http://host.docker.internal:4000/v1"
    )
    assert (
        launcher._container_base_url("https://api.example.test/v1")
        == "https://api.example.test/v1"
    )


def test_render_output_is_mapped_into_trace_mount(tmp_path: Path) -> None:
    mapped = launcher._container_arguments(
        ["render", "run-1", "--output", "reports/run-1.html"],
        trace_host=tmp_path,
        trace_container="/workspace/runs",
    )

    assert mapped[-1] == "/workspace/runs/reports/run-1.html"


def test_render_output_cannot_escape_trace_mount(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="inside the configured trace_dir"):
        launcher._container_arguments(
            ["render", "run-1", "--output", "../outside.html"],
            trace_host=tmp_path,
            trace_container="/workspace/runs",
        )


def test_model_requirement_depends_on_business_command() -> None:
    assert launcher._requires_model(["run", "inspect"], default_repl=False)
    assert launcher._requires_model(["doctor", "--live"], default_repl=False)
    assert launcher._requires_model([], default_repl=True)
    assert not launcher._requires_model(["render", "run-id"], default_repl=False)
    assert not launcher._requires_model(["doctor"], default_repl=False)


def test_launcher_rejects_missing_key_before_build(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
active_model = "openai"
workspace = "/workspace"

[models.openai]
provider = "openai"
model = "gpt-test"
base_url = "https://api.example.test/v1"
""".strip(),
        encoding="utf-8",
    )
    built = False

    def fake_build(_root: Path) -> str:
        nonlocal built
        built = True
        return "image:test"

    monkeypatch.setattr(launcher.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(launcher, "_project_root", lambda: tmp_path)
    monkeypatch.setattr(launcher, "_ensure_runtime_image", fake_build)

    result = launcher.main(["--config", str(config_path), "run", "hello"])

    assert result == 2
    assert built is False


def test_launcher_rejects_nonstandard_container_workspace(
    tmp_path: Path, monkeypatch
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
active_model = "openai"
workspace = "/tmp/custom-workspace"

[models.openai]
provider = "openai"
model = "gpt-test"
base_url = "https://api.example.test/v1"
api_key = "test-key"
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(launcher.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(launcher, "_project_root", lambda: tmp_path)

    assert launcher.main(["--config", str(config_path), "run", "hello"]) == 2


def test_local_litellm_uses_generated_virtual_key(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
active_model = "deepseek"
workspace = "/workspace"

[models.deepseek]
provider = "litellm"
model = "deepseek/deepseek-chat"
base_url = "http://host.docker.internal:4000/v1"
""".strip(),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(launcher.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(launcher, "_project_root", lambda: tmp_path)
    monkeypatch.setattr(launcher, "_start_litellm", lambda _root: 0)
    monkeypatch.setattr(
        launcher, "_issue_litellm_virtual_key", lambda _root, _model: "virtual-key"
    )
    monkeypatch.setattr(launcher, "_ensure_runtime_image", lambda _root: "image:test")
    monkeypatch.setattr(launcher.subprocess, "run", fake_run)

    result = launcher.main(["--config", str(config_path), "run", "hello"])

    assert result == 0
    assert captured["env"]["AGENTSECTOOL_MODEL_API_KEY"] == "virtual-key"


def test_generated_litellm_key_is_model_scoped_and_short_lived(
    tmp_path: Path, monkeypatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command, **_kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, stdout="virtual-key\n", stderr="")

    monkeypatch.setattr(launcher.subprocess, "run", fake_run)

    key = launcher._issue_litellm_virtual_key(tmp_path, "deepseek/deepseek-chat")

    assert key == "virtual-key"
    command = captured["command"]
    assert "AGENTSECTOOL_LITELLM_MODEL=deepseek/deepseek-chat" in command
    script = command[-1]
    assert "'duration':'24h'" in script
    assert "'key_alias':'agentsectool-scanner-agent-runtime-'+uuid.uuid4().hex[:12]" in script
    assert "'max_parallel_requests':4" in script
    assert "'models':[os.environ['AGENTSECTOOL_LITELLM_MODEL']]" in script
