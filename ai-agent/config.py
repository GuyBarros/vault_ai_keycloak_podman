from __future__ import annotations

import logging
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from dotenv import load_dotenv
from logging_utils import configure_logging, log_event

load_dotenv()
LOGGER = logging.getLogger("config")


@dataclass
class Settings:
    model: str
    actor_token_path: Path
    token_exchange_url: str
    token_exchange_timeout_seconds: float
    obo_role_name: str
    bypass_auth_token_exchange: bool
    host: str
    port: int
    log_level: str
    user_mcp_url: str
    vault_transform_url: str
    vault_transform_role: str
    vault_token_path: Path
    opa_url: str


def load_settings() -> Settings:
    settings = Settings(
        model=_load_model(),
        actor_token_path=Path(
            os.getenv("ACTOR_TOKEN_PATH", "/vault/secrets/actor-token")
        ),
        token_exchange_url=os.getenv(
            "TOKEN_EXCHANGE_URL", "http://localhost:8080/v1/identity/obo-token"
        ),
        token_exchange_timeout_seconds=float(
            os.getenv("TOKEN_EXCHANGE_TIMEOUT_SECONDS", "20")
        ),
        obo_role_name=os.getenv("OBO_ROLE_NAME", "agent-runtime"),
        bypass_auth_token_exchange=_load_bool(
            "BYPASS_AUTH_TOKEN_EXCHANGE", default=False
        ),
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        user_mcp_url=os.getenv("USER_MCP_URL", "http://localhost:8090/mcp"),
        vault_transform_url=os.getenv(
            "VAULT_TRANSFORM_URL", "http://vault:8200/v1/transform"
        ),
        vault_transform_role=os.getenv("VAULT_TRANSFORM_ROLE", "user-mcp-transform"),
        vault_token_path=Path(
            os.getenv("VAULT_TOKEN_PATH", "/vault/secrets/vault-token")
        ),
        opa_url=os.getenv("OPA_URL", "").rstrip("/"),
    )
    configure_logging(settings.log_level)
    serialized_settings = asdict(settings)
    serialized_settings["actor_token_path"] = str(settings.actor_token_path)
    serialized_settings["vault_token_path"] = str(settings.vault_token_path)
    log_event(LOGGER, "settings_loaded", message="Settings loaded", **serialized_settings)
    return settings


def _load_model() -> str:
    configured_model = os.getenv("LANGCHAIN_MODEL")
    if configured_model:
        return configured_model
    
    return "openai:gpt-5-mini"


def _load_bool(env_name: str, default: bool) -> bool:
    configured_value = os.getenv(env_name)
    if configured_value is None:
        return default

    normalized_value = configured_value.strip().lower()
    if normalized_value in {"1", "true", "yes", "on"}:
        return True
    if normalized_value in {"0", "false", "no", "off"}:
        return False

    raise ValueError(
        f"{env_name} must be one of: 1, true, yes, on, 0, false, no, off."
    )
