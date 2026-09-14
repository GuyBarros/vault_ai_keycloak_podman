from __future__ import annotations

import json
from typing import Any

READ_CREDS_PATH = "database/creds/user-mcp-read-role"
WRITE_CREDS_PATH = "database/creds/user-mcp-write-role"
TRANSFORM_PATH = "transform/encode/user-mcp-transform"
LEASE_REVOKE_PATH = "sys/leases/revoke"


def path_access(path: str, capabilities: list[str]) -> dict[str, Any]:
    return {
        "type": "vault:path_access",
        "path": path,
        "capabilities": list(capabilities),
    }


def authorization_details_for_scopes(scopes: list[str] | tuple[str, ...] | str) -> list[dict[str, Any]]:
    """RFC 9396 vault:path_access entries for the given OAuth scopes."""
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
