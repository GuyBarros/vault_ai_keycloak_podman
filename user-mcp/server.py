from __future__ import annotations

import logging

from auth.jwt_validator import JwtAuthMiddleware, JwtValidator
from config import load_settings
from errors import AppError
from logging_utils import log_event
from mcp_app import build_mcp_app

LOGGER = logging.getLogger("user_mcp.server")

SETTINGS = load_settings()
_MCP, _REPO = build_mcp_app(SETTINGS)


def _build_validator(settings) -> JwtValidator | None:
    if settings.bypass_auth:
        log_event(
            LOGGER,
            "jwt_validation_bypassed",
            level=logging.WARNING,
            message="JWT validation is bypassed (USER_MCP_BYPASS_AUTH=true). Dev only.",
        )
        return None

    jwks_url = settings.effective_jwks_url
    issuer = settings.effective_issuer
    if not jwks_url or not issuer or not settings.audience:
        raise AppError(
            500,
            "configuration_error",
            "USER_MCP_VERIFY_BASE_URL (or USER_MCP_VERIFY_JWKS_URL), "
            "USER_MCP_AUDIENCE, and USER_MCP_ISSUER (or VERIFY_BASE_URL) "
            "must be set when USER_MCP_BYPASS_AUTH is false.",
        )

    return JwtValidator(
        jwks_url=jwks_url,
        audience=settings.audience,
        issuer=issuer,
        jwks_cache_seconds=settings.jwks_cache_seconds,
    )


_VALIDATOR = _build_validator(SETTINGS)

# FastMCP's streamable-HTTP app is a Starlette app mounted at SETTINGS.mount_path.
# We wrap it with our JWT auth middleware so every request is validated before
# FastMCP's session handler runs.
_inner_app = _MCP.http_app(path=SETTINGS.mount_path)
app = JwtAuthMiddleware(
    app=_inner_app,
    validator=_VALIDATOR,
    bypass_auth=SETTINGS.bypass_auth,
    logger=logging.getLogger("user_mcp.auth"),
    allow_unauth_discovery=SETTINGS.allow_unauth_discovery,
)


if __name__ == "__main__":
    import uvicorn

    from logging_utils import build_uvicorn_log_config

    uvicorn.run(
        "server:app",
        host=SETTINGS.host,
        port=SETTINGS.port,
        log_level=SETTINGS.log_level.lower(),
        log_config=build_uvicorn_log_config(SETTINGS.log_level),
    )
