from __future__ import annotations

import json
from typing import Any

READ_CREDS_PATH = "database/creds/user-mcp-read-role"
WRITE_CREDS_PATH = "database/creds/user-mcp-write-role"
TRANSFORM_PATH = "transform/encode/user-mcp-transform"
LEASE_REVOKE_PATH = "sys/leases/revoke"


def authorization_details_for_scopes(scopes: str) -> list[dict[str, Any]]:
    parts = {p for p in scopes.split() if p}
    details: list[dict[str, Any]] = []
    if "users.read" in parts:
        details.append(
            {
                "type": "vault:path_access",
                "path": READ_CREDS_PATH,
                "capabilities": ["read"],
            }
        )
    if "users.write" in parts:
        details.append(
            {
                "type": "vault:path_access",
                "path": WRITE_CREDS_PATH,
                "capabilities": ["read"],
            }
        )
    if details:
        details.append(
            {
                "type": "vault:path_access",
                "path": TRANSFORM_PATH,
                "capabilities": ["create", "update"],
            }
        )
        details.append(
            {
                "type": "vault:path_access",
                "path": LEASE_REVOKE_PATH,
                "capabilities": ["update"],
            }
        )
    return details


def authorization_details_json(scopes: str) -> str:
    return json.dumps(authorization_details_for_scopes(scopes), separators=(",", ":"))
