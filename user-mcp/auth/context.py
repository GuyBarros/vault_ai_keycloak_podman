from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Any, Optional


current_obo_scope: ContextVar[Optional[str]] = ContextVar(
    "current_obo_scope", default=None
)

# The validated human user (JWT `preferred_username`) behind the current
# request. Only ever set for a request that carried a real, signature- and
# claims-validated Bearer token — never for bypass-auth or the anonymous
# discovery identity (see auth/jwt_validator.py). Vault-mode credential
# issuance (storage/postgres_repo.py:_acquire) requires this to be set, so a
# service/client-credentials token with an otherwise-valid scope but no real
# user cannot obtain database credentials.
current_obo_user: ContextVar[Optional[str]] = ContextVar(
    "current_obo_user", default=None
)

# The raw, validated Bearer token itself. Under Vault's native Agentic IAM
# (see docker-compose/templates/vault-setup.sh), this token is presented
# directly to Vault as X-Vault-Token — Vault validates it inline via the
# oauth-resource-server profile and resolves it to an identity/entity, so
# this must only ever be set alongside current_obo_user (same real,
# validated-token requirement — never for bypass-auth or anonymous
# discovery).
current_obo_token: ContextVar[Optional[str]] = ContextVar(
    "current_obo_token", default=None
)

# Group names from the validated OBO JWT (`groups` claim). Used to decide
# whether Vault Transform should mask PII before tool results leave user-mcp.
current_obo_groups: ContextVar[tuple[str, ...]] = ContextVar(
    "current_obo_groups", default=()
)


def bind_request_identity(
    scope: str | None,
    user: str | None = None,
    token: str | None = None,
    groups: tuple[str, ...] | None = None,
) -> tuple[Token[Any], Token[Any], Token[Any], Token[Any]]:
    return (
        current_obo_scope.set(scope),
        current_obo_user.set(user),
        current_obo_token.set(token),
        current_obo_groups.set(groups or ()),
    )


def reset_request_identity(
    tokens: tuple[Token[Any], Token[Any], Token[Any], Token[Any]],
) -> None:
    scope_token, user_token, obo_token, groups_token = tokens
    current_obo_groups.reset(groups_token)
    current_obo_token.reset(obo_token)
    current_obo_user.reset(user_token)
    current_obo_scope.reset(scope_token)


def caller_is_admin() -> bool:
    """True when the validated OBO token includes the Keycloak `admins` group."""
    return "admins" in current_obo_groups.get()
