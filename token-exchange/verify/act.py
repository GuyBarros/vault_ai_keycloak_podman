from __future__ import annotations

import json

import jwt

SPIFFE_PREFIX = "spiffe://example.org/"
PARENT_AGENT_ID = "ai-agent"
CHILD_AGENT_ID = "ai-agent-child"


def spiffe_id(agent_id: str) -> str:
    if agent_id.startswith("spiffe://"):
        return agent_id
    return f"{SPIFFE_PREFIX}{agent_id}"


def act_from_actor_token(
    actor_token: str,
    *,
    child: bool = False,
    nested: dict | None = None,
) -> dict:
    """RFC 8693 act claim. ``act.sub`` is the SPIFFE ID (Vault OAuth alias)."""
    claims: dict = {}
    try:
        decoded = jwt.decode(actor_token, options={"verify_signature": False})
        if isinstance(decoded, dict):
            claims = decoded
    except Exception:
        claims = {}
    parent_id = str(claims.get("agent_id") or PARENT_AGENT_ID)
    if parent_id == CHILD_AGENT_ID:
        parent_id = PARENT_AGENT_ID
    iss = claims.get("iss") if isinstance(claims.get("iss"), str) else None

    agent_id = CHILD_AGENT_ID if child else parent_id

    act: dict = {
        "sub": spiffe_id(agent_id),
        "agent_id": agent_id,
        "spiffe_id": spiffe_id(agent_id),
    }
    if iss:
        act["iss"] = iss
    if nested:
        act["act"] = nested
    elif child:
        parent = {
            "sub": spiffe_id(parent_id),
            "agent_id": parent_id,
            "spiffe_id": spiffe_id(parent_id),
        }
        if iss:
            parent["iss"] = iss
        act["act"] = parent
    return act


def act_json(
    actor_token: str,
    *,
    child: bool = False,
    nested: dict | None = None,
) -> str:
    return json.dumps(act_from_actor_token(actor_token, child=child, nested=nested))
