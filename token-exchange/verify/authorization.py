"""Keycloak Authorization Services (UMA) as the Policy Decision Point (PDP)
for OBO scope grants.

Replaces local groups-claim parsing with a live policy decision: the caller's
own subject_token is presented to Keycloak's uma-ticket grant as the
requesting-party token, and Keycloak evaluates its configured Resources /
Policies / Permissions on the user-mcp client (see
docker-compose/templates/demo-realm.json, or the equivalent live Admin
Console config under Clients > user-mcp > Authorization) to decide which
resources the caller may access. The scopes this service hands out
(users.read / users.write) are only granted when the PDP's live decision
covers the matching resource — group membership changes take effect
immediately, with no redeploy of this service.

Fails closed: any Keycloak error, missing/malformed response, or ungranted
resource denies the scope.
"""
from __future__ import annotations

import requests
import jwt

from config.settings import settings
from exceptions.errors import OBOAuthorizationError, OBORequestError
from app_logging.logger import get_logger

logger = get_logger(__name__)

_UMA_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:uma-ticket"

# Scope this service can grant on an exchanged token -> the Keycloak UMA
# resource name (Clients > user-mcp > Authorization > Resources) that must
# appear in the PDP's decision for that scope to be authorized.
_SCOPE_TO_RESOURCE: dict[str, str] = {
    "users.read": "database-creds-read",
    "users.write": "database-creds-write",
}


def _uma_ticket_url() -> str:
    base = settings.keycloak_url.rstrip("/")
    return f"{base}/realms/{settings.keycloak_realm}/protocol/openid-connect/token"


def fetch_granted_resources(subject_token: str) -> set[str]:
    """Return the UMA resource names Keycloak's PDP grants to *subject_token*'s caller.

    Calls the uma-ticket grant against the ``user-mcp`` resource server,
    presenting *subject_token* as the requesting-party token (Authorization
    header) — Keycloak evaluates it as if that user were asking "what am I
    allowed to do here" directly, with no impersonation involved.
    """
    try:
        response = requests.post(
            _uma_ticket_url(),
            data={
                "grant_type": _UMA_GRANT_TYPE,
                "audience": settings.keycloak_token_exchange_audience,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {subject_token}",
            },
            timeout=10,
        )
    except requests.exceptions.RequestException as exc:
        raise OBORequestError(
            f"Network error contacting Keycloak PDP (UMA): {exc}"
        ) from exc

    if response.status_code == 403:
        # Keycloak's standard response for "no permissions granted" — not a
        # request failure, just an empty decision.
        return set()

    if not response.ok:
        raise OBORequestError(
            "Keycloak PDP (UMA) evaluation failed with HTTP "
            f"{response.status_code}: {response.text[:300]}"
        )

    try:
        rpt = response.json().get("access_token")
    except Exception as exc:
        raise OBORequestError(f"Keycloak PDP (UMA) returned a non-JSON response: {exc}") from exc

    if not rpt:
        raise OBORequestError("Keycloak PDP (UMA) response did not include an access_token")

    try:
        claims = jwt.decode(rpt, options={"verify_signature": False})
    except Exception as exc:
        raise OBORequestError(f"Keycloak PDP (UMA) RPT could not be decoded: {exc}") from exc

    permissions = (claims.get("authorization") or {}).get("permissions") or []
    granted = {
        p.get("rsname")
        for p in permissions
        if isinstance(p, dict) and p.get("rsname")
    }
    logger.info("pdp_decision", granted_resources=sorted(granted))
    return granted


def authorize_scope(subject_token: str, scope: str) -> None:
    """Raise :class:`OBOAuthorizationError` unless Keycloak's PDP grants every
    requested scope that this service governs.

    *scope* is the space-separated string from the request. Scopes this
    module doesn't govern (e.g. ``delegation:ai-agent``) pass through
    untouched — they're authorized by Keycloak's own client-scope consent,
    not by this PDP check.
    """
    requested = [s for s in scope.split() if s]
    governed = [s for s in requested if s in _SCOPE_TO_RESOURCE]
    if not governed:
        return

    granted_resources = fetch_granted_resources(subject_token)

    for requested_scope in governed:
        resource = _SCOPE_TO_RESOURCE[requested_scope]
        if resource not in granted_resources:
            raise OBOAuthorizationError(
                f"Keycloak PDP denied scope '{requested_scope}': resource "
                f"'{resource}' not granted (granted={sorted(granted_resources)})"
            )
