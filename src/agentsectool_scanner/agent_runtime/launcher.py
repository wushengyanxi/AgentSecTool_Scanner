from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence
from urllib.parse import urlsplit, urlunsplit

from pydantic import SecretStr, ValidationError

from agentsectool_scanner.agent_runtime.config import (
    ConfigNotFound,
    MissingApiKey,
    load_config,
    resolve_api_key,
)
from agentsectool_scanner.paths import ROOT as SCANNER_ROOT

_IMAGE_REPOSITORY = "agentsectool-scanner-agent-runtime"
_CODEX_STATE_VOLUME = "agentsectool-scanner-codex-state"
_RUNTIME_RELATIVE = Path("src/agentsectool_scanner/agent_runtime")
_DEPLOY_RELATIVE = _RUNTIME_RELATIVE / "deploy"


def main(
    argv: Sequence[str] | None = None,
    *,
    default_repl: bool = False,
    prog: str = "scanner-agent",
) -> int:
    """Build or reuse the runtime image, then attach the current terminal to it."""

    arguments = list(argv if argv is not None else sys.argv[1:])
    if os.environ.get("AGENTSECTOOL_AGENT_IN_CONTAINER") == "1":
        from agentsectool_scanner.agent_runtime.runtime import main as runtime_main

        return runtime_main(arguments, default_repl=default_repl, prog=prog)

    if any(value in {"-h", "--help"} for value in arguments):
        from agentsectool_scanner.agent_runtime.runtime import main as runtime_main

        return runtime_main(arguments, default_repl=default_repl, prog=prog)

    if shutil.which("docker") is None:
        print("error: Docker CLI is required", file=sys.stderr)
        return 2

    config_path = _config_argument(arguments)
    try:
        config = load_config(config_path)
    except (ConfigNotFound, ValidationError, json.JSONDecodeError) as exc:
        print(f"配置加载失败：{exc}", file=sys.stderr)
        return 2

    try:
        root = _project_root()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if config.workspace != "/workspace":
        print("error: container workspace must be /workspace", file=sys.stderr)
        return 2
    requires_model = _requires_model(arguments, default_repl=default_repl)
    profile = config.active_profile
    api_key = ""
    if requires_model and profile.provider == "litellm" and _uses_local_litellm(profile.base_url):
        compose_result = _start_litellm(root)
        if compose_result != 0:
            return compose_result
        try:
            api_key = resolve_api_key(profile)
        except MissingApiKey:
            api_key = _issue_litellm_virtual_key(root, profile.model) or ""
            if not api_key:
                return 2
    else:
        try:
            api_key = resolve_api_key(profile)
        except MissingApiKey as exc:
            if requires_model:
                print(f"error: {exc}", file=sys.stderr)
                return 2

    trace_host, trace_container = _trace_mount(root, config.trace_dir)
    trace_host.mkdir(parents=True, exist_ok=True)
    try:
        container_args = _container_arguments(
            _remove_config_argument(arguments),
            trace_host=trace_host,
            trace_container=trace_container,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    image = _ensure_runtime_image(root)
    if image is None:
        return 2

    sanitized = config.model_copy(
        update={
            "models": {
                name: profile.model_copy(
                    update={
                        "api_key": SecretStr(""),
                        "base_url": _container_base_url(profile.base_url),
                    }
                )
                for name, profile in config.models.items()
            },
            "trace_dir": trace_container,
        }
    )
    env = os.environ.copy()
    env["AGENTSECTOOL_AGENT_CONFIG_JSON"] = json.dumps(
        sanitized.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")
    )
    env["AGENTSECTOOL_MODEL_API_KEY"] = api_key

    command = [
        "docker",
        "run",
        "--rm",
        "--init",
        "--interactive",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_RAW",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "1g",
        "--cpus",
        "2",
        "--pids-limit",
        "512",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=128m,mode=1777",
        "--tmpfs",
        f"{config.workspace}:rw,nosuid,nodev,size=512m,uid=10001,gid=10001,mode=0700",
        "--mount",
        f"type=volume,src={_CODEX_STATE_VOLUME},dst=/home/scanner/.codex",
        "--mount",
        f"type=bind,src={trace_host},dst={trace_container}",
        "--add-host",
        "host.docker.internal:host-gateway",
        "--env",
        "AGENTSECTOOL_AGENT_CONFIG_JSON",
        "--env",
        "AGENTSECTOOL_MODEL_API_KEY",
        "--env",
        "AGENTSECTOOL_AGENT_IN_CONTAINER=1",
        "--env",
        f"AGENTSECTOOL_AGENT_DEFAULT_REPL={'1' if default_repl else '0'}",
        "--env",
        f"AGENTSECTOOL_AGENT_PROG={prog}",
        "--env",
        "CODEX_HOME=/home/scanner/.codex",
    ]
    if sys.stdin.isatty() and sys.stdout.isatty():
        command.append("--tty")
    command.extend([image, *container_args])
    try:
        return subprocess.run(command, env=env, check=False).returncode
    except KeyboardInterrupt:
        return 130


def cli_entry() -> None:
    raise SystemExit(main())


def repl_entry() -> None:
    raise SystemExit(main(default_repl=True))


def _project_root() -> Path:
    configured = os.environ.get("AGENTSECTOOL_SCANNER_ROOT")
    if configured:
        candidate = Path(configured).expanduser().resolve()
    else:
        candidate = SCANNER_ROOT
    if (candidate / _RUNTIME_RELATIVE / "launcher.py").is_file():
        return candidate
    raise RuntimeError("AgentSecTool Scanner project root could not be located")


def _ensure_runtime_image(root: Path) -> str | None:
    image = f"{_IMAGE_REPOSITORY}:{_source_fingerprint(root)}"
    inspect = subprocess.run(
        ["docker", "image", "inspect", image],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if inspect.returncode == 0:
        return image
    print(f"building runtime image {image}", file=sys.stderr)
    result = subprocess.run(
        [
            "docker",
            "build",
            "--file",
            str(root / _DEPLOY_RELATIVE / "runtime.Dockerfile"),
            "--tag",
            image,
            str(root),
        ],
        check=False,
    )
    return image if result.returncode == 0 else None


def _source_fingerprint(root: Path) -> str:
    runtime_root = root / _RUNTIME_RELATIVE
    paths = [
        runtime_root / "requirements.lock",
        runtime_root / "deploy" / "runtime.Dockerfile",
        root / "src" / "agentsectool_scanner" / "__init__.py",
        root / "src" / "agentsectool_scanner" / "paths.py",
    ]
    paths.extend(
        path
        for path in sorted(runtime_root.rglob("*.py"))
        if "tests" not in path.parts
    )
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


def _start_litellm(root: Path) -> int:
    deploy_root = root / _DEPLOY_RELATIVE
    config_path = deploy_root / "litellm-config.yaml"
    if not config_path.is_file():
        print(
            "error: LiteLLM profile requires agent_runtime/deploy/litellm-config.yaml; "
            "copy the committed example and add local credentials",
            file=sys.stderr,
        )
        return 2
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(deploy_root / "compose.yaml"),
            "up",
            "-d",
            "--wait",
            "--wait-timeout",
            "90",
            "litellm",
        ],
        cwd=deploy_root,
        check=False,
    )
    return result.returncode


def _issue_litellm_virtual_key(root: Path, model: str) -> str | None:
    deploy_root = root / _DEPLOY_RELATIVE
    script = (
        "import json, os, urllib.request, uuid; "
        "payload=json.dumps({'models':[os.environ['AGENTSECTOOL_LITELLM_MODEL']],"
        "'duration':'24h','key_alias':'agentsectool-scanner-agent-runtime-'+uuid.uuid4().hex[:12],"
        "'max_parallel_requests':4}).encode(); "
        "request=urllib.request.Request('http://127.0.0.1:4000/key/generate',"
        "data=payload,headers={'Authorization':'Bearer '+os.environ['LITELLM_MASTER_KEY'],"
        "'Content-Type':'application/json'}); "
        "response=json.load(urllib.request.urlopen(request,timeout=15)); "
        "print(response['key'])"
    )
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(deploy_root / "compose.yaml"),
            "exec",
            "-T",
            "-e",
            f"AGENTSECTOOL_LITELLM_MODEL={model}",
            "litellm",
            "python",
            "-c",
            script,
        ],
        cwd=deploy_root,
        check=False,
        capture_output=True,
        text=True,
    )
    key = result.stdout.strip()
    if result.returncode == 0 and key:
        return key
    message = result.stderr.strip() or "LiteLLM did not return a virtual key"
    print(f"error: unable to issue LiteLLM virtual key: {message}", file=sys.stderr)
    return None


def _uses_local_litellm(base_url: str) -> bool:
    return urlsplit(base_url).hostname in {"localhost", "127.0.0.1", "host.docker.internal"}


def _container_base_url(base_url: str) -> str:
    """Translate host loopback endpoints to the container's host gateway."""

    parsed = urlsplit(base_url)
    if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        return base_url
    port = f":{parsed.port}" if parsed.port is not None else ""
    return urlunsplit(
        (parsed.scheme, f"host.docker.internal{port}", parsed.path, "", "")
    )


def _trace_mount(root: Path, trace_dir: str) -> tuple[Path, str]:
    configured = Path(trace_dir).expanduser()
    if configured.is_absolute():
        return configured, "/workspace/runs"
    return (root / configured).resolve(), "/workspace/runs"


def _container_arguments(
    arguments: Sequence[str], *, trace_host: Path, trace_container: str
) -> list[str]:
    """Map render output paths into the only writable host bind mount."""

    result = list(arguments)
    if "render" not in result:
        return result

    output_index: int | None = None
    output_value: str | None = None
    inline = False
    for index, value in enumerate(result):
        if value in {"--output", "-o"}:
            if index + 1 >= len(result):
                return result
            output_index = index + 1
            output_value = result[output_index]
            break
        if value.startswith("--output="):
            output_index = index
            output_value = value.split("=", 1)[1]
            inline = True
            break
    if output_index is None or output_value is None:
        return result

    trace_root = trace_host.expanduser().resolve()
    requested = Path(output_value).expanduser()
    host_output = (
        requested.resolve()
        if requested.is_absolute()
        else (trace_root / requested).resolve()
    )
    try:
        relative = host_output.relative_to(trace_root)
    except ValueError as exc:
        raise ValueError("render output must be inside the configured trace_dir") from exc
    if relative == Path("."):
        raise ValueError("render output must name an HTML file inside trace_dir")

    mapped = (Path(trace_container) / relative).as_posix()
    result[output_index] = f"--output={mapped}" if inline else mapped
    return result


def _requires_model(arguments: Sequence[str], *, default_repl: bool) -> bool:
    command = next(
        (value for value in arguments if value in {"repl", "run", "render", "doctor"}),
        None,
    )
    if command in {"run", "repl"}:
        return True
    if command == "doctor":
        return "--live" in arguments
    return command is None and default_repl


def _config_argument(arguments: Sequence[str]) -> str | None:
    for index, value in enumerate(arguments):
        if value == "--config" and index + 1 < len(arguments):
            return arguments[index + 1]
        if value.startswith("--config="):
            return value.split("=", 1)[1]
    return None


def _remove_config_argument(arguments: Sequence[str]) -> list[str]:
    cleaned: list[str] = []
    skip = False
    for value in arguments:
        if skip:
            skip = False
            continue
        if value == "--config":
            skip = True
            continue
        if value.startswith("--config="):
            continue
        cleaned.append(value)
    return cleaned
