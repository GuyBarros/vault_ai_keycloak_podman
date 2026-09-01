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


def bind_request_identity(
    scope: str | None, user: str | None = None
) -> tuple[Token[Any], Token[Any]]:
    return current_obo_scope.set(scope), current_obo_user.set(user)


def reset_request_identity(tokens: tuple[Token[Any], Token[Any]]) -> None:
    scope_token, user_token = tokens
    current_obo_user.reset(user_token)
    current_obo_scope.reset(scope_token)
