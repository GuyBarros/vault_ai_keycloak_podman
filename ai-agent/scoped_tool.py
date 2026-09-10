from __future__ import annotations

import logging
from typing import Any

from langchain_core.tools import StructuredTool

from errors import AppError
from identity import OboTokenService
from logging_utils import log_event
from mcp_client import invoke_mcp_tool

LOGGER = logging.getLogger("agent_api.scoped_tool")


def make_scoped_tool(
    template_tool: Any,
    required_scopes: list[str],
    token_service: OboTokenService,
    subject_token: str,
    request_id: str,
    user_mcp_url: str,
) -> StructuredTool:
    """Wrap an MCP tool so each call exchanges its own scope-specific OBO.

    The agent's request handler binds wrappers (not raw MCP tools) to the LLM,
    so when the LLM picks a tool the per-call coroutine:
      1. Looks up the tool's declared `required_scopes` (closed over).
      2. Asks the OboTokenService for a token carrying exactly those scopes
         on behalf of `subject_token` (cached by scope set).
      3. Builds a transient MCP client with that OBO and calls the upstream
         tool with the LLM's args.
      4. On token-exchange failure or `insufficient_scope` from the MCP server,
         returns a human-readable string. LangChain forwards that as a
         ToolMessage so the LLM can apologize / suggest alternatives.
    """
    name = template_tool.name
    description = template_tool.description
    args_schema = getattr(template_tool, "args_schema", None)
    scopes_label = " ".join(sorted(required_scopes))

    async def _coroutine(**kwargs: Any) -> Any:
        try:
            obo_token = token_service.resolve_token(
                subject_token=subject_token,
                request_id=request_id,
                scopes=required_scopes,
            )
        except AppError as exc:
            log_event(
                LOGGER,
                "scoped_tool_token_exchange_failed",
                level=logging.WARNING,
                message=f"Token exchange failed for tool {name}",
                request_id=request_id,
                tool=name,
                required_scopes=scopes_label,
                error=exc.error,
                error_message=exc.message,
            )
            return (
                f"Permission denied: cannot invoke {name} because the OBO token "
                f"exchange for scope(s) {scopes_label} failed: {exc.message}"
            )

        log_event(
            LOGGER,
            "scoped_tool_invoke",
            message=f"Invoking MCP tool {name} with scoped OBO",
            request_id=request_id,
            tool=name,
            required_scopes=scopes_label,
        )

        try:
            return await invoke_mcp_tool(
                user_mcp_url=user_mcp_url,
                tool_name=name,
                args=dict(kwargs),
                obo_token=obo_token,
                request_id=request_id,
            )
        except AppError:
            # invoke_mcp_tool surfaces ext_authz 403s as AppError(403, ...).
            # Let it bubble up so the FastAPI handler can return 403 to the
            # web-app with the upstream authz reason as the message.
            raise
        except Exception as exc:  # noqa: BLE001 - surface broad MCP errors as ToolMessage
            err_text = str(exc)
            if "insufficient_scope" in err_text:
                log_event(
                    LOGGER,
                    "scoped_tool_insufficient_scope",
                    level=logging.WARNING,
                    message=f"MCP server rejected {name} with insufficient_scope",
                    request_id=request_id,
                    tool=name,
                    required_scopes=scopes_label,
                )
                return (
                    f"Permission denied: tool {name} requires scope(s) "
                    f"{scopes_label} which the current user does not have."
                )
            log_event(
                LOGGER,
                "scoped_tool_invoke_failed",
                level=logging.ERROR,
                message=f"MCP tool {name} invocation failed: {err_text}",
                request_id=request_id,
                tool=name,
                required_scopes=scopes_label,
            )
            raise

    return StructuredTool.from_function(
        coroutine=_coroutine,
        name=name,
        description=description,
        args_schema=args_schema,
    )
