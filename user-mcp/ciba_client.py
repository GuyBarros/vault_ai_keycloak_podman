from __future__ import annotations

import asyncio
import logging

import httpx

from errors import AppError
from logging_utils import log_event

LOGGER = logging.getLogger("user_mcp.ciba")

_CIBA_GRANT = "urn:openid:params:grant-type:ciba"


class CibaClient:
    """Start Keycloak CIBA and poll until the human approves (or timeout)."""

    def __init__(
        self,
        keycloak_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        scope: str = "openid users.read",
        poll_timeout_seconds: float = 110.0,
        approve_url: str = "http://localhost:8093",
    ):
        self._token_url = (
            f"{keycloak_url.rstrip('/')}/realms/{realm}/protocol/openid-connect/token"
        )
        self._auth_url = (
            f"{keycloak_url.rstrip('/')}/realms/{realm}"
            "/protocol/openid-connect/ext/ciba/auth"
        )
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._poll_timeout = poll_timeout_seconds
        self._approve_url = approve_url

    async def fetch_access_token(
        self, login_hint: str, binding_message: str, scope: str | None = None
    ) -> str:
        if not self._client_id or not self._client_secret:
            raise AppError(
                500,
                "configuration_error",
                "CIBA is required by Vault bound_claims but USER_MCP_CIBA_CLIENT_ID "
                "or USER_MCP_CIBA_CLIENT_SECRET is not set.",
            )
        timeout = httpx.Timeout(20.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            start = await client.post(
                self._auth_url,
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "login_hint": login_hint,
                    "scope": scope or self._scope,
                    "binding_message": _binding_message(binding_message),
                },
            )
            body = _json(start)
            if start.status_code >= 400 or "auth_req_id" not in body:
                raise AppError(
                    502,
                    "agent_error",
                    "Keycloak CIBA backchannel request failed "
                    f"(status={start.status_code}): {body}",
                )
            auth_req_id = str(body["auth_req_id"])
            interval = max(int(body.get("interval") or 5), 1)
            log_event(
                LOGGER,
                "ciba_started",
                level=logging.INFO,
                message="Vault required CIBA; waiting for human approval",
                login_hint=login_hint,
                binding_message=binding_message,
                approve_url=self._approve_url,
            )
            elapsed = 0.0
            while elapsed < self._poll_timeout:
                await asyncio.sleep(interval)
                elapsed += interval
                poll = await client.post(
                    self._token_url,
                    data={
                        "grant_type": _CIBA_GRANT,
                        "auth_req_id": auth_req_id,
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                    },
                )
                token_body = _json(poll)
                if poll.status_code == 200 and token_body.get("access_token"):
                    log_event(
                        LOGGER,
                        "ciba_approved",
                        level=logging.INFO,
                        message="CIBA approved; using Keycloak JWT for Vault login",
                        login_hint=login_hint,
                    )
                    return str(token_body["access_token"])
                err = str(token_body.get("error") or "")
                if err == "slow_down":
                    interval += 5
                    continue
                if err in ("authorization_pending",):
                    continue
                if err in ("access_denied", "expired_token"):
                    log_event(
                        LOGGER,
                        "ciba_denied",
                        level=logging.INFO,
                        message="CIBA was denied or expired",
                        login_hint=login_hint,
                        preferred_username=login_hint,
                        ciba_error=err,
                    )
                    raise AppError(
                        403,
                        "invalid_request",
                        "CIBA was denied or expired. Approve the request at "
                        f"{self._approve_url} and retry.",
                    )
                raise AppError(
                    502,
                    "agent_error",
                    f"Keycloak CIBA token poll failed (status={poll.status_code}): "
                    f"{token_body}",
                )
        raise AppError(
            403,
            "invalid_request",
            "Timed out waiting for CIBA approval. Open "
            f"{self._approve_url}, approve the pending request, and retry.",
        )


def _binding_message(text: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in text)
    cleaned = cleaned.strip("-")[:50]
    return cleaned or "write"


def _json(resp: httpx.Response) -> dict:
    try:
        body = resp.json()
    except ValueError:
        return {"raw": resp.text[:400]}
    return body if isinstance(body, dict) else {"raw": str(body)[:400]}
