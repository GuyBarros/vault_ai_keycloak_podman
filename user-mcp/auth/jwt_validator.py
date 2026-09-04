from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Awaitable, Callable

import jwt
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from auth.context import bind_request_identity, reset_request_identity
from errors import AppError
from logging_utils import bind_log_context, log_event, reset_log_context


_BYPASS_IDENTITY: dict[str, Any] = {
    "preferred_username": "bypass",
    "agent_id": "bypass",
    "scope": "",
    "sub": "bypass",
    "raw": {},
}

_ANONYMOUS_DISCOVERY_IDENTITY: dict[str, Any] = {
    "preferred_username": "anonymous",
    "agent_id": "discovery",
    "scope": "",
    "sub": "anonymous",
    "raw": {},
}


class JwtValidator:
    """Validates Keycloak-issued OBO JWTs against signature, audience,
    issuer, and time claims."""

    def __init__(
        self,
        jwks_url: str,
        audience: str,
        issuer: str,
        jwks_cache_seconds: int,
        algorithms: list[str] | None = None,
        leeway_seconds: int = 30,
    ):
        if not jwks_url:
            raise ValueError("jwks_url is required for JwtValidator.")
        if not audience:
            raise ValueError("audience is required for JwtValidator.")
        if not issuer:
            raise ValueError("issuer is required for JwtValidator.")

        self._jwks_client = jwt.PyJWKClient(
            jwks_url,
            cache_keys=True,
            lifespan=jwks_cache_seconds,
        )
        self._audience = audience
        self._issuer = issuer
        self._algorithms = algorithms or ["RS256"]
        self._leeway = leeway_seconds

    def validate(self, token: str) -> dict[str, Any]:
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token).key
        except jwt.PyJWKClientError as exc:
            raise AppError(401, "invalid_token", f"Unable to fetch signing key: {exc}") from exc
        except jwt.DecodeError as exc:
            raise AppError(401, "invalid_token", f"Malformed token: {exc}") from exc

        try:
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=self._algorithms,
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "aud", "iss"]},
                leeway=self._leeway,
            )
        except jwt.ExpiredSignatureError as exc:
            raise AppError(401, "expired_token", "Bearer token has expired.") from exc
        except jwt.InvalidAudienceError as exc:
            raise AppError(401, "invalid_audience", "Token audience does not match this service.") from exc
        except jwt.InvalidIssuerError as exc:
            raise AppError(401, "invalid_issuer", "Token issuer is not trusted.") from exc
        except jwt.InvalidSignatureError as exc:
            raise AppError(401, "invalid_token", "Token signature is invalid.") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise AppError(401, "invalid_token", f"Token is missing required claim: {exc.claim}") from exc
        except jwt.InvalidTokenError as exc:
            raise AppError(401, "invalid_token", f"Token is invalid: {exc}") from exc

        return claims


def extract_identity(claims: dict[str, Any]) -> dict[str, Any]:
    """Pull the fields we care about for downstream logging / authorization."""
    def _normalize_scope(value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (list, tuple, set)):
            return " ".join(str(s) for s in value if str(s).strip())
        return ""

    scope_claim = _normalize_scope(claims.get("scope"))
    if not scope_claim:
        scope_claim = _normalize_scope(claims.get("scp"))
    actor_claim = claims.get("actor")
    agent_id = actor_claim.get("agent_id") if isinstance(actor_claim, dict) else None
    raw_groups = claims.get("groups")
    groups: tuple[str, ...] = ()
    if isinstance(raw_groups, list):
        groups = tuple(
            str(g).lstrip("/")
            for g in raw_groups
            if isinstance(g, str) and g.strip()
        )
    return {
        "preferred_username": claims.get("preferred_username"),
        "agent_id": agent_id,
        "scope": scope_claim,
        "sub": claims.get("sub"),
        "groups": groups,
        "raw": claims,
    }


class JwtAuthMiddleware:
    """ASGI middleware that validates the OBO bearer token on every HTTP
    request, binds identity to the log context, and stores claims in the
    request scope for downstream handlers."""

    def __init__(
        self,
        app: ASGIApp,
        validator: JwtValidator | None,
        bypass_auth: bool,
        logger: logging.Logger,
        allow_unauth_discovery: bool = False,
    ):
        self._app = app
        self._validator = validator
        self._bypass_auth = bypass_auth
        self._allow_unauth_discovery = allow_unauth_discovery
        self._logger = logger
        if not bypass_auth and validator is None:
            raise ValueError(
                "JwtValidator is required when bypass_auth is False."
            )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        request_id = _resolve_request_id(scope)

        if self._bypass_auth:
            identity = dict(_BYPASS_IDENTITY)
            scope_state = scope.setdefault("state", {})
            scope_state["jwt_claims"] = identity
            scope_state["jwt_token"] = None
            await self._dispatch_with_context(scope, receive, send, identity, request_id)
            return

        try:
            token = _extract_bearer(scope)
            claims = self._validator.validate(token)
        except AppError as exc:
            # Allow unauthenticated discovery requests through with an anonymous
            # identity when the operator opts in. Real tools/call invocations
            # are still rejected downstream by scope_check (empty scope ⇒
            # insufficient_scope); only tools/list will succeed.
            if (
                self._allow_unauth_discovery
                and exc.error == "invalid_request"
                and exc.message == "Authorization bearer token is required."
            ):
                identity = dict(_ANONYMOUS_DISCOVERY_IDENTITY)
                scope_state = scope.setdefault("state", {})
                scope_state["jwt_claims"] = identity
                scope_state["jwt_token"] = None
                log_event(
                    self._logger,
                    "discovery_unauth_request",
                    message="Accepting unauthenticated MCP discovery request",
                    request_id=request_id,
                )
                await self._dispatch_with_context(scope, receive, send, identity, request_id)
                return

            log_event(
                self._logger,
                "jwt_validation_failed",
                level=logging.WARNING,
                message=f"JWT validation failed: {exc.message}",
                request_id=request_id,
                error=exc.error,
                status_code=exc.status_code,
            )
            await _send_error(send, exc.status_code, exc.error, exc.message, request_id)
            return

        identity = extract_identity(claims)
        scope_state = scope.setdefault("state", {})
        scope_state["jwt_claims"] = identity
        scope_state["jwt_token"] = token
        await self._dispatch_with_context(
            scope, receive, send, identity, request_id,
            verified_user=identity.get("preferred_username"),
        )

    async def _dispatch_with_context(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        identity: dict[str, Any],
        request_id: str,
        verified_user: str | None = None,
    ) -> None:
        """Run the wrapped app with request-scoped log context and identity bound.

        `verified_user` is deliberately NOT derived from `identity` here — it
        must only ever be a `preferred_username` that came off a signature-
        and claims-validated Bearer token. The bypass-auth and anonymous-
        discovery call sites both omit it (leaving it None), so
        `current_obo_user` (auth/context.py) can be trusted downstream as
        "a real user was authenticated for this request" — Vault-mode
        credential issuance depends on that being true.
        """
        log_token = bind_log_context(
            request_id=request_id,
            preferred_username=identity.get("preferred_username"),
            agent_id=identity.get("agent_id"),
            auth_scope=identity.get("scope"),
        )
        identity_token = bind_request_identity(
            scope=identity.get("scope"),
            user=verified_user,
            groups=identity.get("groups") or (),
            token=scope_state.get("jwt_token"),
        )
        try:
            wrapped_send = _build_request_id_send(send, request_id)
            await self._app(scope, receive, wrapped_send)
        finally:
            reset_request_identity(identity_token)
            reset_log_context(log_token)


def _extract_bearer(scope: Scope) -> str:
    headers = dict(scope.get("headers") or [])
    raw = headers.get(b"authorization")
    if raw is None:
        raise AppError(401, "invalid_request", "Authorization bearer token is required.")
    value = raw.decode("latin-1").strip()
    parts = value.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise AppError(401, "invalid_request", "Authorization header must use Bearer scheme.")
    return parts[1].strip()


def _resolve_request_id(scope: Scope) -> str:
    headers = dict(scope.get("headers") or [])
    raw = headers.get(b"x-request-id")
    if raw is not None:
        candidate = raw.decode("latin-1").strip()
        if candidate:
            return candidate
    return str(uuid.uuid4())


async def _send_error(
    send: Send,
    status_code: int,
    error: str,
    message: str,
    request_id: str,
) -> None:
    body = json.dumps({"error": error, "message": message}, ensure_ascii=True).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"x-request-id", request_id.encode("latin-1")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


def _build_request_id_send(send: Send, request_id: str) -> Callable[[Message], Awaitable[None]]:
    async def wrapped(message: Message) -> None:
        if message["type"] == "http.response.start":
            headers = list(message.get("headers") or [])
            if not any(name == b"x-request-id" for name, _ in headers):
                headers.append((b"x-request-id", request_id.encode("latin-1")))
            message = {**message, "headers": headers}
        await send(message)

    return wrapped
