from __future__ import annotations

import logging

import httpx

from errors import AppError
from logging_utils import log_event

LOGGER = __import__("logging").getLogger("agent_api.lifecycle")


def assert_agent_onboarded(
    vault_addr: str,
    vault_token: str,
    display_name: str = "ai-agent",
) -> None:
    """Fail closed unless the agent is registered, owned, and enabled.

    Video: identity + accountable owner, then lifecycle (onboard / suspend).
    Missing KV or missing registry record is not a pass — it is not onboarded.
    """
    if not vault_token:
        raise AppError(
            status_code=403,
            error="agent_not_onboarded",
            message="This agent has no Vault token to prove it is onboarded.",
        )
    headers = {"X-Vault-Token": vault_token}
    timeout = 5.0
    try:
        registry = httpx.get(
            f"{vault_addr.rstrip('/')}/v1/agent-registry/registration/display-name/{display_name}",
            headers=headers,
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise AppError(
            status_code=403,
            error="agent_not_onboarded",
            message=f"Could not read agent registry for {display_name}: {exc}",
        ) from exc
    if registry.status_code >= 400:
        raise AppError(
            status_code=403,
            error="agent_not_onboarded",
            message=(
                f"Agent {display_name} is not in the Vault agent registry. "
                "An owner must register it before it can act."
            ),
        )
    body = registry.json() if registry.content else {}
    data = body.get("data") or {}
    owner = str(data.get("owner") or "").strip()
    if not owner:
        raise AppError(
            status_code=403,
            error="agent_not_onboarded",
            message=(
                f"Agent {display_name} has no accountable owner in the registry."
            ),
        )

    try:
        resp = httpx.get(
            f"{vault_addr.rstrip('/')}/v1/agent-lifecycle/data/{display_name}",
            headers=headers,
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise AppError(
            status_code=403,
            error="agent_not_onboarded",
            message=f"Could not read agent lifecycle for {display_name}: {exc}",
        ) from exc
    if resp.status_code >= 400:
        raise AppError(
            status_code=403,
            error="agent_not_onboarded",
            message=(
                f"Agent {display_name} is not onboarded. An owner must "
                f"`vault kv put agent-lifecycle/{display_name} enabled=true`."
            ),
        )
    kv = resp.json() if resp.content else {}
    data = (kv.get("data") or {}).get("data") or kv.get("data") or {}
    enabled = str(data.get("enabled", "")).strip().lower()
    if enabled in {"false", "0", "no"}:
        log_event(
            LOGGER,
            "agent_suspended",
            level=logging.WARNING,
            message="Agent lifecycle flag is disabled; refusing to act",
            owner=owner,
        )
        raise AppError(
            status_code=403,
            error="agent_suspended",
            message="This agent is suspended. An owner must re-enable it in Vault "
            f"(agent-lifecycle/{display_name} enabled=true) before it can act.",
        )
    if enabled not in {"true", "1", "yes"}:
        raise AppError(
            status_code=403,
            error="agent_not_onboarded",
            message=(
                f"Agent {display_name} is registered but not enabled. "
                "Onboard with enabled=true."
            ),
        )
    log_event(
        LOGGER,
        "agent_onboarded",
        message="Agent registry + lifecycle allow this act",
        display_name=display_name,
        owner=owner,
    )


def assert_agent_enabled(vault_addr: str, vault_token: str) -> None:
    """Back-compat name used by agent_api."""
    assert_agent_onboarded(vault_addr, vault_token)
