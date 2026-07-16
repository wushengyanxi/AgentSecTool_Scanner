from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentsectool_scanner.agent_runtime.config import Config, MissingApiKey, load_config, resolve_api_key


def test_example_config_loads_without_committed_secret() -> None:
    path = Path("config/agent-runtime.example.toml")

    config = load_config(path)

    assert config.active_model == "openai"
    assert set(config.models) == {"openai", "deepseek"}
    with pytest.raises(MissingApiKey):
        resolve_api_key(config.active_profile)


def test_active_model_must_reference_a_profile() -> None:
    with pytest.raises(ValidationError, match="unknown profile"):
        Config(
            active_model="missing",
            models={
                "openai": {
                    "provider": "openai",
                    "model": "gpt-test",
                    "base_url": "https://api.example.test/v1",
                }
            },
        )


def test_legacy_runtime_fields_fail_instead_of_being_ignored() -> None:
    with pytest.raises(ValidationError, match="provider_source"):
        Config(
            active_model="openai",
            models={
                "openai": {
                    "provider": "openai",
                    "model": "gpt-test",
                    "base_url": "https://api.example.test/v1",
                }
            },
            provider_source="remote",
        )


def test_api_key_is_not_exposed_by_model_dump() -> None:
    config = Config(
        active_model="openai",
        models={
            "openai": {
                "provider": "openai",
                "model": "gpt-test",
                "base_url": "https://api.example.test/v1",
                "api_key": "secret-value",
            }
        },
    )

    dumped = config.model_dump(mode="json")

    assert dumped["models"]["openai"]["api_key"] == "**********"
    assert resolve_api_key(config.active_profile) == "secret-value"


def test_container_config_injects_key_from_environment(monkeypatch) -> None:
    monkeypatch.setenv(
        "AGENTSECTOOL_AGENT_CONFIG_JSON",
        json.dumps(
            {
                "active_model": "openai",
                "models": {
                    "openai": {
                        "provider": "openai",
                        "model": "gpt-test",
                        "base_url": "https://api.example.test/v1",
                        "api_key": "",
                    }
                },
            }
        ),
    )
    monkeypatch.setenv("AGENTSECTOOL_MODEL_API_KEY", "injected-secret")

    config = load_config()

    assert resolve_api_key(config.active_profile) == "injected-secret"


@pytest.mark.parametrize(
    "base_url",
    [
        "http://api.example.test/v1",
        "https://user:password@api.example.test/v1",
        "https://api.example.test/v1?token=secret",
    ],
)
def test_remote_model_endpoint_rejects_insecure_urls(base_url: str) -> None:
    with pytest.raises(ValidationError, match="base_url"):
        Config(
            active_model="openai",
            models={
                "openai": {
                    "provider": "openai",
                    "model": "gpt-test",
                    "base_url": base_url,
                }
            },
        )
