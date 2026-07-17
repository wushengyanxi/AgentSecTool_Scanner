"""Local configuration for the derivation agent."""

from __future__ import annotations

import configparser
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from agentsectool_scanner.paths import DERIVATION_CONFIG


class DerivationConfigError(ValueError):
    """Raised when local agent configuration is missing or unsafe."""


@dataclass(frozen=True)
class AgentConfig:
    api_key: str
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-5.6"
    reasoning_effort: str = "high"
    timeout_seconds: int = 300
    allow_external_model: bool = False
    allowed_domains: tuple[str, ...] = (
        "github.com",
        "docs.github.com",
        "docker.com",
        "hub.docker.com",
    )

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and self.allow_external_model)


def load_agent_config(path: str | Path = DERIVATION_CONFIG) -> AgentConfig:
    config_path = Path(path)
    parser = configparser.ConfigParser()
    if config_path.is_file():
        parser.read(config_path, encoding="utf-8")
    api_key = parser.get("openai", "api_key", fallback="").strip()
    base_url = parser.get("openai", "base_url", fallback="https://api.openai.com/v1").strip()
    model = parser.get("openai", "model", fallback="gpt-5.6").strip()
    effort = parser.get("openai", "reasoning_effort", fallback="high").strip()
    timeout = parser.getint("openai", "timeout_seconds", fallback=300)
    allowed = tuple(
        value.strip().lower()
        for value in parser.get(
            "research",
            "allowed_domains",
            fallback="github.com,docs.github.com,docker.com,hub.docker.com",
        ).split(",")
        if value.strip()
    )
    result = AgentConfig(
        api_key=api_key,
        base_url=base_url.rstrip("/"),
        model=model,
        reasoning_effort=effort,
        timeout_seconds=timeout,
        allow_external_model=parser.getboolean(
            "authorization", "allow_external_model", fallback=False
        ),
        allowed_domains=allowed,
    )
    validate_agent_config(result)
    return result


def validate_agent_config(config: AgentConfig) -> None:
    parsed = urlparse(config.base_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise DerivationConfigError("OpenAI base_url 必须是有效的 HTTPS 地址")
    if not config.model:
        raise DerivationConfigError("OpenAI model 不能为空")
    if config.reasoning_effort not in {"none", "low", "medium", "high", "xhigh", "max"}:
        raise DerivationConfigError("reasoning_effort 不在支持范围内")
    if not 10 <= config.timeout_seconds <= 1800:
        raise DerivationConfigError("timeout_seconds 必须在 10 到 1800 秒之间")
    if not config.allowed_domains:
        raise DerivationConfigError("至少需要配置一个可信检索域名")
    for domain in config.allowed_domains:
        if "/" in domain or ":" in domain or domain.startswith("."):
            raise DerivationConfigError(f"检索域名格式无效：{domain}")


def config_status(path: str | Path = DERIVATION_CONFIG) -> dict:
    try:
        config = load_agent_config(path)
    except DerivationConfigError as exc:
        return {"configured": False, "authorized": False, "error": str(exc)}
    return {
        "configured": bool(config.api_key),
        "authorized": config.allow_external_model,
        "enabled": config.enabled,
        "model": config.model,
        "base_url": config.base_url,
        "allowed_domains": list(config.allowed_domains),
    }
