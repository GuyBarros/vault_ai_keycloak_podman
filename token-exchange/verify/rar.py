from __future__ import annotations

import json
from typing import Any

READ_CREDS_PATH = "database/creds/user-mcp-read-role"
WRITE_CREDS_PATH = "database/creds/user-mcp-write-role"
TRANSFORM_PATH = "transform/encode/user-mcp-transform"
LEASE_REVOKE_PATH = "sys/leases/revoke"


def path_access(
    path: str,
    capabilities: list[str],
    operation_details: dict[str, Any] | None = None,
    allowed_parameters: dict[str, list[str]] | None = None,
    required_parameters: list[str] | None = None,
) -> dict[str, Any]:
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


def authorization_details_for_scopes(scopes: str) -> list[dict[str, Any]]:
    """Path-only fallback when the OBO request has no tool-bound RAR."""
    parts = {p for p in scopes.split() if p}
    details: list[dict[str, Any]] = []
    if "users.read" in parts:
        details.append(path_access(READ_CREDS_PATH, ["read"]))
    if "users.write" in parts:
        details.append(path_access(WRITE_CREDS_PATH, ["read"]))
    if details:
        details.append(path_access(TRANSFORM_PATH, ["create", "update"]))
        details.append(path_access(LEASE_REVOKE_PATH, ["update"]))
    return details


def authorization_details_json(scopes: str) -> str:
    return json.dumps(authorization_details_for_scopes(scopes), separators=(",", ":"))
