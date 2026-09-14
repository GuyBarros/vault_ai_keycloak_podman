from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import StructuredTool

from errors import AppError
from identity import OboTokenService
from logging_utils import log_event
from mcp_client import invoke_mcp_tool

LOGGER = __import__("logging").getLogger("agent_api.delegate")


def make_delegate_research_tool(
    token_service: OboTokenService,
    subject_token: str,
    request_id: str,
    user_mcp_url: str,
) -> StructuredTool:
    """Parent→child sandbox: child OBO is users.read only.

    The child can list users. A write with the same child token is denied by
    Vault RAR / MCP scope — matching OpenShell scenario 3.
    """

    async def _coroutine(task: str = "list users then attempt a write") -> str:
        log_event(
            LOGGER,
            "delegate_research_started",
            message="Delegating to read-only child OBO",
            request_id=request_id,
            task=task,
        )
        child_obo = token_service.resolve_token(
            subject_token=subject_token,
            request_id=request_id,
            scopes=["users.read"],
            child=True,
        )
        token_service.last_child_obo_token = child_obo

        listed = await invoke_mcp_tool(
            user_mcp_url=user_mcp_url,
            tool_name="list_all_users",
            args={},
            obo_token=child_obo,
            request_id=request_id,
        )
        write_result: Any
        try:
            write_result = await invoke_mcp_tool(
                user_mcp_url=user_mcp_url,
                tool_name="create_user",
                args={
                    "user": {
                        "first_name": "Child",
                        "last_name": "Denied",
                        "email": "child-denied@demo.com",
                    }
                },
                obo_token=child_obo,
                request_id=request_id,
            )
        except AppError as exc:
            write_result = {
                "ok": False,
                "denied": True,
                "error": "access_denied",
                "detail": exc.message,
            }
        except Exception as exc:  # noqa: BLE001
            write_result = {
                "ok": False,
                "denied": True,
                "error": "access_denied",
                "detail": str(exc),
            }

        payload = {
            "child_scope": ["users.read"],
            "read": listed,
            "write_attempt": write_result,
        }
        return json.dumps(payload, default=str)

    return StructuredTool.from_function(
        coroutine=_coroutine,
        name="delegate_research",
        description=(
            "Delegate a read-only investigation to a sandboxed child identity. "
            "The child can list users. Any write it attempts is denied by policy. "
            "Use this when the user asks to delegate, sandbox, or prove that a "
            "child agent cannot write."
        ),
    )
