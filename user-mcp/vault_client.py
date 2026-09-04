from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from errors import AppError
from logging_utils import log_event

LOGGER = logging.getLogger("user_mcp.vault")


@dataclass(frozen=True)
class DynamicDbCredentials:
    username: str
    password: str
    lease_id: str
    lease_duration: int


class VaultClient:
    """Thin async Vault client for the JWT login + database creds flow.

    Authenticates to Vault with a SPIFFE JWT-SVID (this workload's own
    identity, fetched from the local SPIRE Workload API — see
    spiffe_client.py) to obtain a short-lived Vault client token, then reads
    dynamic Postgres credentials from the database secrets engine using that
    token. Which Vault role to request (read vs. write) is still selected by
    the caller from the human user's validated OIDC scope.
    """

    def __init__(
        self,
        addr: str,
        jwt_path: str,
        namespace: str | None = None,
        verify_tls: bool | str = True,
        timeout_seconds: float = 10.0,
    ):
        if not addr:
            raise AppError(
                500,
                "configuration_error",
                "USER_MCP_VAULT_ADDR is required when USER_MCP_DB_AUTH_MODE=vault.",
            )
        self._addr = addr.rstrip("/")
        self._jwt_path = jwt_path.strip("/")
        self._namespace = namespace or None
        self._verify_tls = verify_tls
        self._timeout = httpx.Timeout(timeout_seconds)

    def _headers(self, client_token: str | None = None) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace
        if client_token:
            headers["X-Vault-Token"] = client_token
        return headers

    async def login_with_jwt(
        self,
        jwt_token: str,
        role: str,
        user_metadata: dict[str, str] | None = None,
    ) -> str:
        """Login to Vault using a JWT token and return the client token.

        user_metadata is forwarded in the login payload so Vault stores it on
        the resulting entity alias — it appears in audit logs and token metadata
        as auth.metadata.* fields, giving full attribution of which agent and
        tool triggered each credential issuance.
        """
        url = f"{self._addr}/v1/auth/{self._jwt_path}/login"
        payload: dict = {"role": role, "jwt": jwt_token}
        if user_metadata:
            payload["user_metadata"] = user_metadata
        try:
            async with httpx.AsyncClient(verify=self._verify_tls, timeout=self._timeout) as client:
                resp = await client.post(url, json=payload, headers=self._headers())
        except httpx.HTTPError as exc:
            raise AppError(
                502,
                "agent_error",
                f"Vault login failed (transport): {exc}",
            ) from exc

        if resp.status_code >= 400:
            raise AppError(
                _vault_status_to_app_status(resp.status_code),
                _vault_status_to_app_error(resp.status_code),
                f"Vault JWT login rejected (status={resp.status_code}): {_safe_error_body(resp)}",
            )

        body = resp.json()
        auth = body.get("auth") or {}
        client_token = auth.get("client_token")
        if not client_token:
            raise AppError(
                502,
                "agent_error",
                "Vault login response did not include auth.client_token.",
            )
        log_event(
            LOGGER,
            "vault_login_ok",
            level=logging.INFO,
            message="Vault JWT login succeeded",
            vault_role=role,
            jwt_path=self._jwt_path,
        )
        return client_token

    async def transform_encode(
        self,
        client_token: str,
        role: str,
        transformation: str,
        value: str,
    ) -> str:
        """Encode/mask a value using Vault Transform Secret Engine."""
        url = f"{self._addr}/v1/transform/encode/{role}"
        payload = {"value": value, "transformation": transformation}
        try:
            async with httpx.AsyncClient(verify=self._verify_tls, timeout=self._timeout) as client:
                resp = await client.post(url, json=payload, headers=self._headers(client_token))
        except httpx.HTTPError as exc:
            raise AppError(502, "agent_error", f"Vault transform encode failed (transport): {exc}") from exc

        if resp.status_code >= 400:
            raise AppError(
                _vault_status_to_app_status(resp.status_code),
                _vault_status_to_app_error(resp.status_code),
                f"Vault transform encode rejected (status={resp.status_code}): {_safe_error_body(resp)}",
            )
        body = resp.json()
        encoded = (body.get("data") or {}).get("encoded_value")
        if encoded is None:
            raise AppError(502, "agent_error", "Vault transform encode response missing encoded_value.")
        log_event(
            LOGGER,
            "vault_transform_encode_ok",
            level=logging.DEBUG,
            message="Vault transform encode succeeded",
            transformation=transformation,
        )
        return encoded

    async def read_database_creds(
        self, client_token: str, creds_path: str
    ) -> DynamicDbCredentials:
        path = creds_path.strip("/")
        url = f"{self._addr}/v1/{path}"
        try:
            async with httpx.AsyncClient(verify=self._verify_tls, timeout=self._timeout) as client:
                resp = await client.get(url, headers=self._headers(client_token))
        except httpx.HTTPError as exc:
            raise AppError(
                502,
                "agent_error",
                f"Vault DB creds fetch failed (transport): {exc}",
            ) from exc

        if resp.status_code >= 400:
            raise AppError(
                _vault_status_to_app_status(resp.status_code),
                _vault_status_to_app_error(resp.status_code),
                f"Vault DB creds fetch rejected (status={resp.status_code}): {_safe_error_body(resp)}",
            )

        body = resp.json()
        data = body.get("data") or {}
        username = data.get("username")
        password = data.get("password")
        if not username or not password:
            raise AppError(
                502,
                "agent_error",
                "Vault DB creds response missing username/password.",
            )
        log_event(
            LOGGER,
            "vault_db_creds_issued",
            level=logging.INFO,
            message="Vault issued dynamic DB credentials",
            creds_path=path,
            lease_duration=body.get("lease_duration"),
        )
        return DynamicDbCredentials(
            username=username,
            password=password,
            lease_id=body.get("lease_id", ""),
            lease_duration=int(body.get("lease_duration", 0) or 0),
        )


def _vault_status_to_app_status(status: int) -> int:
    if status in (400, 403):
        return 403
    if status == 404:
        return 404
    return 502


def _vault_status_to_app_error(status: int) -> str:
    if status in (400, 401, 403):
        return "invalid_request"
    return "agent_error"


def _safe_error_body(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:500]
    errors = body.get("errors") if isinstance(body, dict) else None
    if isinstance(errors, list) and errors:
        return "; ".join(str(e) for e in errors)
    return str(body)[:500]
