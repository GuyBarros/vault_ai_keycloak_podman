from __future__ import annotations

import logging

import httpx

from errors import AppError
from logging_utils import log_event

LOGGER = __import__("logging").getLogger("agent_api.lifecycle")


def assert_agent_enabled(vault_addr: str, vault_token: str) -> None:
    """Fail closed when the owner has suspended the agent (KV flag)."""
    if not vault_token:
        return
    url = f"{vault_addr.rstrip('/')}/v1/agent-lifecycle/data/ai-agent"
    try:
        resp = httpx.get(
            url,
            headers={"X-Vault-Token": vault_token},
            timeout=5.0,
        )
    except httpx.HTTPError:
        return
    if resp.status_code >= 400:
        return
    body = resp.json() if resp.content else {}
    data = (body.get("data") or {}).get("data") or body.get("data") or {}
    enabled = str(data.get("enabled", "true")).strip().lower()
    if enabled in {"false", "0", "no"}:
        log_event(
            LOGGER,
            "agent_suspended",
            level=logging.WARNING,
            message="Agent lifecycle flag is disabled; refusing to act",
        )
        raise AppError(
            status_code=403,
            error="agent_suspended",
            message="This agent is suspended. An owner must re-enable it in Vault "
            "(agent-lifecycle/ai-agent enabled=true) before it can act.",
        )
