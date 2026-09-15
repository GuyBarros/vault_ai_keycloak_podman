from __future__ import annotations

from typing import Any

from auth.context import current_obo_authorization_details
from errors import AppError


class ResourceMismatchError(AppError):
    """Raised when the tool invocation does not match the RAR bound in the OBO.

    This is the OpenShell poisoned-ticket beat: a grant for KAN-3 (here an
    email / first_name) cannot be reused for another resource.
    """

    def __init__(self, *, tool: str, granted: dict[str, Any], requested: dict[str, Any]):
        message = (
            f"Tool '{tool}' is not authorized by this grant: "
            f"token bound {granted} but invocation is {requested}."
        )
        super().__init__(403, "insufficient_scope", message)
        self.tool = tool
        self.granted = granted
        self.requested = requested


_BYPASS = False

RESOURCE_TOOLS = frozenset(
    {
        "create_user",
        "delete_user_by_email",
        "update_user_by_email",
        "search_users_by_first_name",
    }
)


def configure_bypass(enabled: bool) -> None:
    global _BYPASS
    _BYPASS = enabled


def operation_details_from(details: list[Any] | None) -> dict[str, Any]:
    """First vault:path_access operationDetails on a creds path (not transform/lease)."""
    for item in details or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "vault:path_access":
            continue
        path = str(item.get("path") or "")
        if "database/creds/" not in path:
            continue
        op = item.get("operationDetails")
        if isinstance(op, dict):
            return dict(op)
    return {}


def _requested(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    requested: dict[str, Any] = {"action": tool_name}
    email = args.get("email")
    if isinstance(email, str) and email.strip():
        requested["email"] = email.strip().lower()
    user = args.get("user")
    if isinstance(user, dict):
        nested = user.get("email")
        if isinstance(nested, str) and nested.strip():
            requested["email"] = nested.strip().lower()
    first_name = args.get("first_name")
    if isinstance(first_name, str) and first_name.strip():
        requested["first_name"] = first_name.strip()
    return requested


SENSITIVE_EMAILS = frozenset({"admin@demo.com"})


def email_is_sensitive(email: str) -> bool:
    """Patient-record analogue: HITL even when the tool itself is silent."""
    value = (email or "").strip().lower()
    if not value:
        return False
    if value in SENSITIVE_EMAILS:
        return True
    local = value.split("@", 1)[0]
    return local in {"sensitive", "patient", "ceo"} or value.startswith("patient@")


def jwt_authorization_details(token: str) -> list[Any]:
    if not token:
        return []
    try:
        import jwt

        claims = jwt.decode(token, options={"verify_signature": False})
    except Exception:  # noqa: BLE001
        return []
    raw = claims.get("authorization_details") if isinstance(claims, dict) else None
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def assert_token_rar_allows_path(token: str, creds_path: str) -> None:
    """Refuse to mint a Vault lease unless the JWT RAR covers this path + resource.

    Vault OAuth RS only enforces type/path/capabilities. This is the demo's
    extra gate so action details actually control the ephemeral credential.
    """
    if _BYPASS:
        return
    expected = operation_details_from(current_obo_authorization_details.get())
    details = jwt_authorization_details(token)
    if not details:
        if expected:
            raise ResourceMismatchError(
                tool=str(expected.get("action") or creds_path),
                granted={},
                requested={"path": creds_path, **expected},
            )
        return
    paths = {
        str(item.get("path") or "")
        for item in details
        if item.get("type") == "vault:path_access"
    }
    if creds_path not in paths:
        raise ResourceMismatchError(
            tool=creds_path,
            granted={"paths": sorted(p for p in paths if p)},
            requested={"path": creds_path},
        )
    granted = operation_details_from(details)
    if not expected:
        return
    if expected.get("action") and granted.get("action") != expected.get("action"):
        raise ResourceMismatchError(tool=str(expected.get("action")), granted=granted, requested=expected)
    if expected.get("email") and granted.get("email") != expected.get("email"):
        raise ResourceMismatchError(tool=str(expected.get("action")), granted=granted, requested=expected)
    if expected.get("first_name") and str(granted.get("first_name") or "").casefold() != str(
        expected.get("first_name") or ""
    ).casefold():
        raise ResourceMismatchError(tool=str(expected.get("action")), granted=granted, requested=expected)


def require_rar(tool_name: str, args: dict[str, Any] | None = None) -> None:
    """Deny if the OBO grant's action/resource does not match this invocation."""
    if _BYPASS:
        return

    granted = operation_details_from(current_obo_authorization_details.get())
    requested = _requested(tool_name, args or {})

    if not granted:
        # Path-only tokens (password-grant prove scripts) have no tool binding.
        # Agent OBOs always carry operationDetails. Fail closed for writes.
        if tool_name in RESOURCE_TOOLS:
            raise ResourceMismatchError(
                tool=tool_name,
                granted={},
                requested=requested,
            )
        return

    if granted.get("action") != tool_name:
        raise ResourceMismatchError(tool=tool_name, granted=granted, requested=requested)

    if tool_name in ("create_user", "delete_user_by_email", "update_user_by_email"):
        granted_email = str(granted.get("email") or "").strip().lower()
        requested_email = str(requested.get("email") or "").strip().lower()
        if not granted_email or granted_email != requested_email:
            raise ResourceMismatchError(tool=tool_name, granted=granted, requested=requested)

    if tool_name == "search_users_by_first_name":
        granted_name = str(granted.get("first_name") or "").strip()
        requested_name = str(requested.get("first_name") or "").strip()
        if not granted_name or granted_name.casefold() != requested_name.casefold():
            raise ResourceMismatchError(tool=tool_name, granted=granted, requested=requested)
