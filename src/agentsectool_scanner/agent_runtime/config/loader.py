from __future__ import annotations

import json
import os
import tomllib
from pathlib import Path

from pydantic import SecretStr

from agentsectool_scanner.agent_runtime.config.schema import Config, ModelProfileConfig
from agentsectool_scanner.paths import AGENT_RUNTIME_CONFIG, AGENT_RUNTIME_CONFIG_EXAMPLE

CONFIG_ENV_VAR = "AGENTSECTOOL_AGENT_CONFIG"
CONFIG_JSON_ENV_VAR = "AGENTSECTOOL_AGENT_CONFIG_JSON"


class ConfigNotFound(Exception):
    def __init__(self, path: Path) -> None:
        super().__init__(f"配置文件不存在：{path}")
        self.path = path


class MissingApiKey(RuntimeError):
    pass


def default_config_path() -> Path:
    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path:
        return Path(env_path).expanduser()
    if AGENT_RUNTIME_CONFIG.is_file():
        return AGENT_RUNTIME_CONFIG
    return AGENT_RUNTIME_CONFIG_EXAMPLE


def load_config(path: str | Path | None = None) -> Config:
    config_json = os.environ.get(CONFIG_JSON_ENV_VAR) if path is None else None
    if config_json:
        data = json.loads(config_json)
        config = Config(**data)
        injected_key = os.environ.get("AGENTSECTOOL_MODEL_API_KEY", "")
        if injected_key:
            models = dict(config.models)
            models[config.active_model] = config.active_profile.model_copy(
                update={"api_key": SecretStr(injected_key)}
            )
            config = config.model_copy(update={"models": models})
        return config
    config_path = Path(path).expanduser() if path is not None else default_config_path()
    if not config_path.is_file():
        raise ConfigNotFound(config_path)
    data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    return Config(**data)


def resolve_api_key(profile: ModelProfileConfig) -> str:
    api_key = profile.api_key.get_secret_value().strip()
    if api_key:
        return api_key
    raise MissingApiKey(
        "当前模型档案缺少 api_key；请在被 Git 忽略的本地配置文件中填写"
    )
