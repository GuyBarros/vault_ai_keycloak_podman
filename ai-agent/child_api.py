"""Child sandbox runtime — separate process, SPIFFE ai-agent-child, uid 1001.

The parent agent POSTs /v1/child/research. This process is the only one that
reads the child actor token and runs the child LLM / MCP calls.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from config import load_settings
from errors import AppError
from identity import OboTokenService
from logging_utils import bind_log_context, log_event, reset_log_context
from mcp_client import invoke_mcp_tool
from rar import authorization_details_json_for_tool

LOGGER = logging.getLogger("child_api")
SETTINGS = load_settings()
TOKEN_SERVICE = OboTokenService(settings=SETTINGS, logger=LOGGER)
app = FastAPI(title="ai-agent-child")


class ChildResearchRequest(BaseModel):
    subject_token: str
    task: str = "list users then attempt a write"
    request_id: str = Field(default="")


@app.middleware("http")
async def _bind_request_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id
    token = bind_log_context(request_id=request_id, path=request.url.path, actor_agent_id="ai-agent-child")
    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
    finally:
        reset_log_context(token)


@app.exception_handler(AppError)
async def _app_error(_request: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.error, "message": exc.message},
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "agent_id": "ai-agent-child", "runtime": "separate"}


@app.post("/v1/child/research")
async def research(body: ChildResearchRequest) -> dict[str, Any]:
    request_id = body.request_id or str(uuid.uuid4())
    log_event(
        LOGGER,
        "child_research_started",
        message="Child sandbox received a delegated task",
        request_id=request_id,
        task=body.task,
    )
    child_obo = TOKEN_SERVICE.resolve_token(
        subject_token=body.subject_token,
        request_id=request_id,
        scopes=["users.read"],
        child=True,
        authorization_details=authorization_details_json_for_tool("list_all_users", {}),
    )
    listed = await invoke_mcp_tool(
        user_mcp_url=SETTINGS.user_mcp_url,
        tool_name="list_all_users",
        args={},
        obo_token=child_obo,
        request_id=request_id,
    )
    write_result: Any
    try:
        write_result = await invoke_mcp_tool(
            user_mcp_url=SETTINGS.user_mcp_url,
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
            "error": exc.error,
            "detail": exc.message,
        }
    except Exception as exc:  # noqa: BLE001
        write_result = {
            "ok": False,
            "denied": True,
            "error": "access_denied",
            "detail": str(exc),
        }
    summary = await _child_llm_summary(body.task, listed, write_result)
    return {
        "runtime": "ai-agent-child",
        "child_scope": ["users.read"],
        "task": body.task,
        "read": listed,
        "write_attempt": write_result,
        "summary": summary,
        "child_obo_token": child_obo,
    }


async def _child_llm_summary(task: str, listed: Any, write_result: Any) -> str:
    """Best-effort child LLM note. Identity work already happened without it."""
    import os

    model = os.getenv("LANGCHAIN_MODEL", "")
    if not model:
        denied = isinstance(write_result, dict) and write_result.get("denied")
        return (
            f"Child runtime listed users for {task!r}. "
            f"Write denied by policy={bool(denied)}."
        )
    try:
        from langchain.chat_models import init_chat_model

        llm = init_chat_model(model, timeout=30)
        msg = (
            "You are a sandboxed child agent with users.read only. "
            f"Task: {task}. A write was attempted and policy denied it. "
            "Reply in one sentence that you completed the read-only research."
        )
        result = await llm.ainvoke(msg)
        text = getattr(result, "content", None) or str(result)
        return text if isinstance(text, str) else str(text)
    except Exception as exc:  # noqa: BLE001
        log_event(
            LOGGER,
            "child_llm_unavailable",
            level=logging.WARNING,
            message=f"Child LLM skipped: {exc}",
        )
        return f"Child runtime finished without LLM ({exc})."
