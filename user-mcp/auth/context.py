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

# Group names from the validated OBO JWT (`groups` claim). Used to decide
# whether Vault Transform should mask PII before tool results leave user-mcp.
current_obo_groups: ContextVar[tuple[str, ...]] = ContextVar(
    "current_obo_groups", default=()
)

# Raw validated Bearer token presented to Vault JWT login (jwt-keycloak).
# Only set when a real user was authenticated — never for bypass/discovery.
current_obo_token: ContextVar[Optional[str]] = ContextVar(
    "current_obo_token", default=None
)

# Vault-issued combined action token (human + user-mcp). Secret calls
# (database/creds, transform) must use this token, never the SPIFFE or
# jwt-keycloak login tokens.
current_vault_action_token: ContextVar[Optional[str]] = ContextVar(
    "current_vault_action_token", default=None
)



def bind_request_identity(
    scope: str | None,
    user: str | None = None,
    groups: tuple[str, ...] | None = None,
    token: str | None = None,
) -> tuple[Token[Any], Token[Any], Token[Any], Token[Any]]:
    return (
        current_obo_scope.set(scope),
        current_obo_user.set(user),
        current_obo_groups.set(groups or ()),
        current_obo_token.set(token),
    )


def reset_request_identity(
    tokens: tuple[Token[Any], Token[Any], Token[Any], Token[Any]],
) -> None:
    scope_token, user_token, groups_token, obo_token = tokens
    current_obo_token.reset(obo_token)
    current_obo_groups.reset(groups_token)
    current_obo_user.reset(user_token)
    current_obo_scope.reset(scope_token)


def caller_is_admin() -> bool:
    """True when the validated OBO token includes the Keycloak `admins` group."""
    return "admins" in current_obo_groups.get()
