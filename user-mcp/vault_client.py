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

    Authenticates to Vault with a JWT — SPIFFE JWT-SVID for workload
    attestation, Keycloak OBO for human identity. Neither login token
    can call secrets. Vault then mints a third action token (token role)
    that is the only identity allowed to read database/creds or Transform.
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
        self, jwt_token: str, role: str, jwt_path: str | None = None
    ) -> str:
        path = (jwt_path or self._jwt_path).strip("/")
        url = f"{self._addr}/v1/auth/{path}/login"
        payload = {"role": role, "jwt": jwt_token}
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
            jwt_path=path,
        )
        return client_token

    async def create_action_token(
        self,
        parent_token: str,
        role: str,
        display_name: str,
        meta: dict[str, str],
        ttl: str = "60s",
        approver_token: str | None = None,
    ) -> str:
        """Mint the combined user+workload identity via a Vault token role.

        The human JWT login may only request auth/token/create/<role>. Vault
        Control Groups require a SPIFFE-authenticated member of
        user-mcp-workload to authorize that request. Unwrap then yields the
        only token permitted to call database/creds and Transform.
        """
        url = f"{self._addr}/v1/auth/token/create/{role}"
        payload = {
            "display_name": display_name[:32],
            "meta": meta,
            "ttl": ttl,
            "renewable": False,
        }
        try:
            async with httpx.AsyncClient(verify=self._verify_tls, timeout=self._timeout) as client:
                resp = await client.post(
                    url, json=payload, headers=self._headers(parent_token)
                )
                body = _json_body(resp)
        except httpx.HTTPError as exc:
            raise AppError(
                502,
                "agent_error",
                f"Vault action-token create failed (transport): {exc}",
            ) from exc

        wrap = body.get("wrap_info") or {}
        data = body.get("data") or {}
        wrap_token = wrap.get("token") or data.get("token")
        wrap_accessor = wrap.get("accessor") or data.get("accessor")
        wrapped_accessor = wrap.get("wrapped_accessor") or data.get("wrapped_accessor")
        if wrap_token and wrap_accessor:
            if not approver_token:
                raise AppError(
                    403,
                    "invalid_request",
                    "Vault action-token mint requires SPIFFE control-group "
                    "approval; the human JWT alone cannot unwrap the combined "
                    "identity.",
                )
            try:
                await self._authorize_control_group(approver_token, wrap_accessor)
            except AppError:
                if wrapped_accessor and wrapped_accessor != wrap_accessor:
                    await self._authorize_control_group(
                        approver_token, wrapped_accessor
                    )
                else:
                    raise
            client_token = await self._unwrap_token(wrap_token)
            log_event(
                LOGGER,
                "vault_action_token_ok",
                level=logging.INFO,
                message="Vault minted combined user+workload action identity",
                vault_role=role,
                display_name=display_name[:32],
                control_group="authorized",
            )
            return client_token

        if resp.status_code >= 400:
            raise AppError(
                _vault_status_to_app_status(resp.status_code),
                _vault_status_to_app_error(resp.status_code),
                f"Vault action-token create rejected (status={resp.status_code}): "
                f"{_safe_error_body(resp)}",
            )

        raise AppError(
            502,
            "agent_error",
            "Vault action-token create did not activate a control group; "
            "refusing to use a token minted without SPIFFE approval.",
        )

    async def _authorize_control_group(self, approver_token: str, accessor: str) -> None:
        url = f"{self._addr}/v1/sys/control-group/authorize"
        try:
            async with httpx.AsyncClient(verify=self._verify_tls, timeout=self._timeout) as client:
                resp = await client.post(
                    url,
                    json={"accessor": accessor},
                    headers=self._headers(approver_token),
                )
        except httpx.HTTPError as exc:
            raise AppError(
                502,
                "agent_error",
                f"Vault control-group authorize failed (transport): {exc}",
            ) from exc
        if resp.status_code >= 400:
            raise AppError(
                _vault_status_to_app_status(resp.status_code),
                _vault_status_to_app_error(resp.status_code),
                f"Vault control-group authorize rejected (status={resp.status_code}): "
                f"{_safe_error_body(resp)}",
            )
        log_event(
            LOGGER,
            "vault_control_group_ok",
            level=logging.INFO,
            message="SPIFFE identity authorized the action-token control group",
        )

    async def _unwrap_token(self, wrapping_token: str) -> str:
        url = f"{self._addr}/v1/sys/wrapping/unwrap"
        try:
            async with httpx.AsyncClient(verify=self._verify_tls, timeout=self._timeout) as client:
                resp = await client.post(url, headers=self._headers(wrapping_token))
        except httpx.HTTPError as exc:
            raise AppError(
                502,
                "agent_error",
                f"Vault unwrap failed (transport): {exc}",
            ) from exc
        if resp.status_code >= 400:
            raise AppError(
                _vault_status_to_app_status(resp.status_code),
                _vault_status_to_app_error(resp.status_code),
                f"Vault unwrap rejected (status={resp.status_code}): "
                f"{_safe_error_body(resp)}",
            )
        body = _json_body(resp)
        client_token = (body.get("auth") or {}).get("client_token")
        if not client_token:
            raise AppError(
                502,
                "agent_error",
                "Vault unwrap response did not include auth.client_token.",
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


def _json_body(resp: httpx.Response) -> dict:
    try:
        body = resp.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _safe_error_body(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:500]
    errors = body.get("errors") if isinstance(body, dict) else None
    if isinstance(errors, list) and errors:
        return "; ".join(str(e) for e in errors)
    return str(body)[:500]
