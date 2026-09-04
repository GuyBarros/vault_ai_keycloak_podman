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

# The raw, validated OBO Bearer token string for the current request.
# Set only when bypass_auth is False and a real user was authenticated.
# Used by postgres_repo to pass the OBO token directly to Vault's
# jwt-keycloak auth mount for database credential issuance.
current_obo_token: ContextVar[Optional[str]] = ContextVar(
    "current_obo_token", default=None
)

# The agent_id from the OBO token's may_act.preferred_username claim.
# Keycloak's delegation scope maps the acting service's username here.
current_agent_id: ContextVar[Optional[str]] = ContextVar(
    "current_agent_id", default=None
)

# The MCP tool name currently being executed. Set by tools/users.py before
# each tool body runs so postgres_repo can include it in Vault user_metadata.
current_tool_name: ContextVar[Optional[str]] = ContextVar(
    "current_tool_name", default=None
)


def bind_request_identity(
    scope: str | None,
    user: str | None = None,
    groups: tuple[str, ...] | None = None,
    token: str | None = None,
    agent_id: str | None = None,
) -> tuple[Token[Any], Token[Any], Token[Any], Token[Any], Token[Any]]:
    return (
        current_obo_scope.set(scope),
        current_obo_user.set(user),
        current_obo_groups.set(groups or ()),
        current_obo_token.set(token),
        current_agent_id.set(agent_id),
    )


def reset_request_identity(
    tokens: tuple[Token[Any], Token[Any], Token[Any], Token[Any], Token[Any]],
) -> None:
    scope_token, user_token, groups_token, token_token, agent_token = tokens
    current_obo_groups.reset(groups_token)
    current_obo_user.reset(user_token)
    current_obo_scope.reset(scope_token)
    current_obo_token.reset(token_token)
    current_agent_id.reset(agent_token)


def caller_is_admin() -> bool:
    """True when the validated OBO token includes the Keycloak `admins` group."""
    return "admins" in current_obo_groups.get()
