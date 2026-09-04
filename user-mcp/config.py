from __future__ import annotations

import logging
from typing import Literal

from dotenv import load_dotenv
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from errors import AppError
from logging_utils import configure_logging, log_event

load_dotenv()
LOGGER = logging.getLogger("user_mcp.config")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
    )

    # HTTP / process
    host: str = Field(default="0.0.0.0", alias="USER_MCP_HOST")
    port: int = Field(default=8090, alias="USER_MCP_PORT")
    mount_path: str = Field(default="/mcp", alias="USER_MCP_PATH")
    log_level: str = Field(default="INFO", alias="USER_MCP_LOG_LEVEL")

    # JWT validation
    verify_base_url: str = Field(default="", alias="USER_MCP_VERIFY_BASE_URL")
    verify_jwks_url: str = Field(default="", alias="USER_MCP_VERIFY_JWKS_URL")
    audience: str = Field(default="", alias="USER_MCP_AUDIENCE")
    issuer: str = Field(default="", alias="USER_MCP_ISSUER")
    jwks_cache_seconds: int = Field(default=3600, alias="USER_MCP_JWKS_CACHE_SECONDS")
    bypass_auth: bool = Field(default=False, alias="USER_MCP_BYPASS_AUTH")
    # When true, requests with no Authorization header are dispatched with an
    # anonymous identity (empty scope). The downstream scope_check still rejects
    # any tools/call (no scope ⇒ insufficient_scope), but tools/list succeeds —
    # which is what the agent uses for one-shot startup discovery over a
    # network channel that's already secured at the mesh layer.
    allow_unauth_discovery: bool = Field(
        default=False, alias="USER_MCP_ALLOW_UNAUTH_DISCOVERY"
    )

    # Storage backend
    user_backend: Literal["file", "postgres"] = Field(default="file", alias="USER_BACKEND")
    users_file: str = Field(default="./users_repository.json", alias="USER_MCP_USERS_FILE")

    # Postgres connection (URL without credentials; user/password injected per mode below)
    pg_url: str = Field(default="", alias="USER_MCP_PG_URL")
    pg_auto_migrate: bool = Field(default=False, alias="USER_MCP_AUTO_MIGRATE")

    # DB credential source: "direct" (static USER_MCP_DB_USER/PASSWORD, for connectivity tests)
    # or "vault" (short-lived creds minted by Vault using the OBO token; production default).
    db_auth_mode: Literal["direct", "vault"] = Field(default="vault", alias="USER_MCP_DB_AUTH_MODE")

    # Direct DB credentials (only used when USER_MCP_DB_AUTH_MODE=direct)
    db_user: str = Field(default="", alias="USER_MCP_DB_USER")
    db_password: str = Field(default="", alias="USER_MCP_DB_PASSWORD")

    # Vault (only used when USER_MCP_DB_AUTH_MODE=vault)
    vault_addr: str = Field(default="", alias="USER_MCP_VAULT_ADDR")
    vault_namespace: str = Field(default="", alias="USER_MCP_VAULT_NAMESPACE")

    # Keycloak OBO JWT auth: Vault bound_claims on groups + scope decide
    # read vs write DB creds. Required in addition to SPIFFE below.
    vault_jwt_path: str = Field(default="jwt-keycloak", alias="USER_MCP_VAULT_JWT_PATH")
    vault_jwt_read_role: str = Field(
        default="user-mcp-oidc-read", alias="USER_MCP_VAULT_JWT_READ_ROLE"
    )
    vault_jwt_write_role: str = Field(
        default="user-mcp-oidc-write", alias="USER_MCP_VAULT_JWT_WRITE_ROLE"
    )
    vault_action_read_role: str = Field(
        default="user-mcp-action-read", alias="USER_MCP_VAULT_ACTION_READ_ROLE"
    )
    vault_action_write_role: str = Field(
        default="user-mcp-action-write", alias="USER_MCP_VAULT_ACTION_WRITE_ROLE"
    )

    # SPIFFE workload identity: every Vault DB-cred request first logs in
    # with this process's JWT-SVID (bound_subject = user-mcp). That login
    # has no secret policy — it only attests the workload. The combined
    # Vault action token is what calls database/creds and Transform.
    spiffe_socket: str = Field(default="", alias="USER_MCP_SPIFFE_SOCKET")
    spiffe_jwt_audience: str = Field(default="", alias="USER_MCP_SPIFFE_JWT_AUDIENCE")
    vault_spiffe_jwt_path: str = Field(default="jwt-spiffe", alias="USER_MCP_VAULT_SPIFFE_JWT_PATH")
    vault_spiffe_workload_role: str = Field(
        default="user-mcp-spiffe", alias="USER_MCP_VAULT_SPIFFE_WORKLOAD_ROLE"
    )
    vault_spiffe_transform_role: str = Field(
        default="user-mcp-spiffe-transform", alias="USER_MCP_VAULT_SPIFFE_TRANSFORM_ROLE"
    )
    vault_db_read_path: str = Field(
        default="database/creds/user-mcp-read-role",
        alias="USER_MCP_VAULT_DB_READ_PATH",
    )
    vault_db_write_path: str = Field(
        default="database/creds/user-mcp-write-role",
        alias="USER_MCP_VAULT_DB_WRITE_PATH",
    )
    vault_verify_tls: bool = Field(default=True, alias="USER_MCP_VAULT_VERIFY_TLS")
    vault_ca_bundle: str = Field(default="", alias="USER_MCP_VAULT_CA_BUNDLE")
    vault_request_timeout_seconds: float = Field(
        default=10.0, alias="USER_MCP_VAULT_TIMEOUT_SECONDS"
    )

    # Vault Transform Secret Engine (PII masking)
    transform_enabled: bool = Field(default=False, alias="USER_MCP_TRANSFORM_ENABLED")
    transform_role: str = Field(default="", alias="USER_MCP_TRANSFORM_ROLE")

    @field_validator("log_level")
    @classmethod
    def _normalize_level(cls, value: str) -> str:
        return value.upper()

    @property
    def effective_issuer(self) -> str:
        return self.issuer or self.verify_base_url

    @property
    def effective_jwks_url(self) -> str:
        if self.verify_jwks_url:
            return self.verify_jwks_url
        if not self.verify_base_url:
            return ""
        # Keycloak standard JWKS endpoint for a realm.
        return self.verify_base_url.rstrip("/") + "/protocol/openid-connect/certs"


def _validate_compatibility(settings: Settings) -> None:
    """Catch deploy-time misconfigurations before the first request hits.

    Vault-mode DB credentials require a SPIFFE workload login and a Keycloak
    OBO JWT (see storage/postgres_repo.py:_acquire). Bypass mode discards the
    Authorization header entirely (see auth/jwt_validator.py: bypass branch),
    so there is no user token to present and Vault login cannot succeed — the
    two together produce a service that always 500s on tools/call.
    """
    if (
        settings.bypass_auth
        and settings.user_backend == "postgres"
        and settings.db_auth_mode == "vault"
    ):
        raise AppError(
            500,
            "configuration_error",
            "USER_MCP_BYPASS_AUTH=true is incompatible with "
            "USER_MCP_DB_AUTH_MODE=vault: vault mode requires a validated "
            "user scope on every tool call to select the Vault role, but "
            "bypass mode discards the Authorization header. Set "
            "USER_MCP_BYPASS_AUTH=false (rely on "
            "USER_MCP_ALLOW_UNAUTH_DISCOVERY=true for ai-agent's startup "
            "tools/list) or set USER_MCP_DB_AUTH_MODE=direct.",
        )


def load_settings() -> Settings:
    settings = Settings()
    configure_logging(settings.log_level)
    _validate_compatibility(settings)
    log_event(
        LOGGER,
        "settings_loaded",
        message="Settings loaded",
        host=settings.host,
        port=settings.port,
        mount_path=settings.mount_path,
        log_level=settings.log_level,
        user_backend=settings.user_backend,
        users_file=settings.users_file if settings.user_backend == "file" else None,
        pg_url_configured=bool(settings.pg_url) if settings.user_backend == "postgres" else None,
        db_auth_mode=settings.db_auth_mode if settings.user_backend == "postgres" else None,
        vault_addr=settings.vault_addr if settings.user_backend == "postgres" and settings.db_auth_mode == "vault" else None,
        verify_issuer=settings.effective_issuer or None,
        verify_audience=settings.audience or None,
        verify_jwks_url=settings.effective_jwks_url or None,
        bypass_auth=settings.bypass_auth,
        allow_unauth_discovery=settings.allow_unauth_discovery,
        transform_enabled=settings.transform_enabled,
        transform_role=settings.transform_role or None,
    )
    return settings
