from __future__ import annotations

import json
from typing import Any

READ_CREDS_PATH = "database/creds/user-mcp-read-role"
WRITE_CREDS_PATH = "database/creds/user-mcp-write-role"
TRANSFORM_PATH = "transform/encode/user-mcp-transform"
LEASE_REVOKE_PATH = "sys/leases/revoke"

# Tool → OAuth scope. Same contract as user-mcp TOOL_SCOPE_REQUIREMENTS.
TOOL_SCOPES: dict[str, str] = {
    "list_all_users": "users.read",
    "search_users_by_first_name": "users.read",
    "create_user": "users.write",
    "delete_user_by_email": "users.write",
    "update_user_by_email": "users.write",
}


def path_access(
    path: str,
    capabilities: list[str],
    operation_details: dict[str, Any] | None = None,
    allowed_parameters: dict[str, list[str]] | None = None,
    required_parameters: list[str] | None = None,
) -> dict[str, Any]:
    """RFC 9396 ``vault:path_access`` Vault 2.1 actually evaluates.

    ``allowed_parameters`` / ``required_parameters`` are native RAR fields
    (not OpenShell extras). Vault intersects them with the request to
    ``database/creds`` so action details gate the ephemeral credential.
    ``operationDetails`` stays for the inspector / MCP poisoned-ticket check.
    """
    entry: dict[str, Any] = {
        "type": "vault:path_access",
        "path": path,
        "capabilities": list(capabilities),
    }
    if operation_details:
        entry["operationDetails"] = dict(operation_details)
    if allowed_parameters:
        entry["allowed_parameters"] = {
            key: list(values) for key, values in allowed_parameters.items()
        }
    if required_parameters:
        entry["required_parameters"] = list(required_parameters)
    return entry


def _email_from_args(args: dict[str, Any]) -> str:
    email = args.get("email")
    if isinstance(email, str) and email.strip():
        return email.strip().lower()
    user = args.get("user")
    if isinstance(user, dict):
        nested = user.get("email")
        if isinstance(nested, str) and nested.strip():
            return nested.strip().lower()
    return ""


def _first_name_from_args(args: dict[str, Any]) -> str:
    value = args.get("first_name")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return ""


def operation_details_for_tool(tool_name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    """Video-style action + resource. Jira issue_key → email / first_name here."""
    args = args or {}
    details: dict[str, Any] = {"action": tool_name}
    if tool_name in ("create_user", "delete_user_by_email", "update_user_by_email"):
        email = _email_from_args(args)
        if email:
            details["email"] = email
    if tool_name == "search_users_by_first_name":
        first_name = _first_name_from_args(args)
        if first_name:
            details["first_name"] = first_name
    return details


def authorization_details_for_tool(
    tool_name: str, args: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    scope = TOOL_SCOPES.get(tool_name)
    if not scope:
        return []
    op = operation_details_for_tool(tool_name, args)
    allowed: dict[str, list[str]] = {}
    required: list[str] = []
    if op.get("email"):
        allowed["email"] = [str(op["email"])]
        required.append("email")
    if op.get("first_name"):
        allowed["first_name"] = [str(op["first_name"])]
        required.append("first_name")
    details: list[dict[str, Any]] = []
    if scope == "users.read":
        details.append(
            path_access(
                READ_CREDS_PATH,
                ["read"],
                op,
                allowed_parameters=allowed or None,
                required_parameters=required or None,
            )
        )
    elif scope == "users.write":
        details.append(
            path_access(
                WRITE_CREDS_PATH,
                ["read"],
                op,
                allowed_parameters=allowed or None,
                required_parameters=required or None,
            )
        )
    if details:
        details.append(path_access(TRANSFORM_PATH, ["create", "update"]))
        details.append(path_access(LEASE_REVOKE_PATH, ["update"]))
    return details


def authorization_details_for_scopes(scopes: list[str] | tuple[str, ...] | str) -> list[dict[str, Any]]:
    """Path-only fallback when the caller has no tool context (prove scripts)."""
    if isinstance(scopes, str):
        parts = {p for p in scopes.split() if p}
    else:
        parts = {p for p in scopes if p}
    details: list[dict[str, Any]] = []
    if "users.read" in parts:
        details.append(path_access(READ_CREDS_PATH, ["read"]))
    if "users.write" in parts:
        details.append(path_access(WRITE_CREDS_PATH, ["read"]))
    if details:
        details.append(path_access(TRANSFORM_PATH, ["create", "update"]))
        details.append(path_access(LEASE_REVOKE_PATH, ["update"]))
    return details


def authorization_details_json(scopes: list[str] | tuple[str, ...] | str) -> str:
    return json.dumps(authorization_details_for_scopes(scopes), separators=(",", ":"))


def authorization_details_json_for_tool(tool_name: str, args: dict[str, Any] | None = None) -> str:
    return json.dumps(authorization_details_for_tool(tool_name, args), separators=(",", ":"))
