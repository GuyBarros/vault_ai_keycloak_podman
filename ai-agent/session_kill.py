from __future__ import annotations

import logging
import os

import httpx

from errors import AppError
from logging_utils import log_event

LOGGER = logging.getLogger("agent_api.session_kill")


def revoke_idp_sessions(username: str) -> bool:
    """End every Keycloak SSO session for *username*.

    That is the IdP half of the video kill: Admin API logout invalidates
    refresh tokens and fires OIDC backchannel logout to the web RP. The RP
    then introspects / drops cookies so the browser must sign in again.
    """
    keycloak_url = os.getenv("KEYCLOAK_URL", "http://keycloak:8080").rstrip("/")
    realm = os.getenv("KEYCLOAK_REALM", "demo")
    admin_user = os.getenv("KEYCLOAK_ADMIN_USER", "admin")
    admin_password = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin")
    if not username or username == "unknown":
        return False
    try:
        token_resp = httpx.post(
            f"{keycloak_url}/realms/master/protocol/openid-connect/token",
            data={
                "client_id": "admin-cli",
                "username": admin_user,
                "password": admin_password,
                "grant_type": "password",
            },
            timeout=8.0,
        )
        token_resp.raise_for_status()
        admin_token = str(token_resp.json().get("access_token") or "")
        if not admin_token:
            return False
        headers = {"Authorization": f"Bearer {admin_token}"}
        users = httpx.get(
            f"{keycloak_url}/admin/realms/{realm}/users",
            params={"username": username, "exact": "true"},
            headers=headers,
            timeout=8.0,
        )
        users.raise_for_status()
        rows = users.json() if users.content else []
        if not rows:
            return False
        user_id = str(rows[0].get("id") or "")
        if not user_id:
            return False
        logout = httpx.post(
            f"{keycloak_url}/admin/realms/{realm}/users/{user_id}/logout",
            headers=headers,
            timeout=8.0,
        )
        ok = logout.status_code in (204, 200)
        log_event(
            LOGGER,
            "idp_session_revoked",
            level=logging.WARNING,
            message="Keycloak sessions ended after repeated unauthorized actions",
            preferred_username=username,
            http=logout.status_code,
        )
        return ok
    except httpx.HTTPError as exc:
        log_event(
            LOGGER,
            "idp_session_revoke_failed",
            level=logging.WARNING,
            message=f"Keycloak session logout failed: {exc}",
            preferred_username=username,
        )
        return False


def raise_session_revoked(username: str) -> None:
    revoke_idp_sessions(username)
    raise AppError(
        status_code=401,
        error="session_revoked",
        message=(
            "Three unauthorized attempts in five minutes. This identity has "
            "no grant for that action. The session was ended at the identity "
            "provider; sign in again."
        ),
    )
