from __future__ import annotations

import json
from typing import Any

import httpx
from langchain_core.tools import StructuredTool

from errors import AppError
from identity import OboTokenService
from logging_utils import log_event

LOGGER = __import__("logging").getLogger("agent_api.delegate")


def make_delegate_research_tool(
    token_service: OboTokenService,
    subject_token: str,
    request_id: str,
    user_mcp_url: str,
    child_runtime_url: str = "",
) -> StructuredTool:
    """Parent→child sandbox: HTTP into the uid-1001 child runtime.

    The parent does not read the child SVID and does not run the child LLM.
    The child process mints its own users.read OBO and policy denies writes.
    """

    async def _coroutine(task: str = "list users then attempt a write") -> str:
        log_event(
            LOGGER,
            "delegate_research_started",
            message="Delegating to child sandbox runtime",
            request_id=request_id,
            task=task,
            child_runtime_url=child_runtime_url,
        )
        if not child_runtime_url:
            raise AppError(
                status_code=500,
                error="agent_error",
                message="CHILD_RUNTIME_URL is not set; child sandbox has no runtime.",
            )
        async with httpx.AsyncClient(timeout=httpx.Timeout(180.0)) as client:
            resp = await client.post(
                f"{child_runtime_url.rstrip('/')}/v1/child/research",
                json={
                    "subject_token": subject_token,
                    "task": task,
                    "request_id": request_id,
                },
            )
        try:
            payload: dict[str, Any] = resp.json()
        except Exception:  # noqa: BLE001
            payload = {"error": resp.text[:500], "http": resp.status_code}
        if resp.status_code >= 400:
            raise AppError(
                status_code=resp.status_code if resp.status_code in (401, 403) else 502,
                error=str(payload.get("error") or "agent_error"),
                message=str(payload.get("message") or payload),
            )
        child_obo = str(payload.get("child_obo_token") or "")
        if child_obo:
            token_service.last_child_obo_token = child_obo
        return json.dumps(payload, default=str)

    return StructuredTool.from_function(
        coroutine=_coroutine,
        name="delegate_research",
        description=(
            "Delegate a read-only investigation to a sandboxed child runtime "
            "(separate process, SPIFFE ai-agent-child, uid 1001). "
            "The child can list users. Any write it attempts is denied by policy. "
            "Use this when the user asks to delegate, sandbox, or prove that a "
            "child agent cannot write."
        ),
    )
