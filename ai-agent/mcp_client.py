from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from errors import AppError
from logging_utils import log_event

LOGGER = logging.getLogger("agent_api.mcp_client")

# LiteLLM master key injected as x-litellm-api-key on every MCP request so
# LiteLLM's admission layer recognises it as a trusted internal caller.
# Falls back to empty string when routing directly to user-mcp (no LiteLLM).
_LITELLM_API_KEY: str = os.environ.get("LITELLM_API_KEY", "ibm123")


def _base_headers(request_id: str) -> dict[str, str]:
    """Return the headers that must accompany every MCP request.

    Includes X-Request-ID for tracing and, when OPENAI_API_KEY is set,
    x-litellm-api-key so LiteLLM's MCP admission layer accepts the call
    regardless of auth_type configuration on the targeted server.
    """
    headers: dict[str, str] = {"X-Request-ID": request_id}
    if _LITELLM_API_KEY:
        headers["x-litellm-api-key"] = f"Bearer {_LITELLM_API_KEY}"
    return headers

# Header set by the OPA/Envoy ext_authz sidecar in front of user-mcp when a
# request is denied — see deploy-k8s/agent-mcp-authz/policy/mcp/authz/mcp_authz.rego.
AUTHZ_REASON_HEADER = "x-authz-reason"


def _find_authz_denied_response(
    exc: BaseException,
    seen: set[int] | None = None,
) -> httpx.Response | None:
    """Walk an exception tree (cause/context and ExceptionGroup members) for an
    httpx 403 carrying an `x-authz-reason` header. The MCP streamable_http
    transport runs requests inside an anyio task group, so the original
    HTTPStatusError can surface wrapped in a BaseExceptionGroup."""
    if seen is None:
        seen = set()
    if id(exc) in seen:
        return None
    seen.add(id(exc))

    if isinstance(exc, httpx.HTTPStatusError):
        response = exc.response
        if response.status_code == 403 and response.headers.get(AUTHZ_REASON_HEADER):
            return response

    if isinstance(exc, BaseExceptionGroup):
        for sub in exc.exceptions:
            found = _find_authz_denied_response(sub, seen)
            if found is not None:
                return found

    for chained in (exc.__cause__, exc.__context__):
        if chained is not None:
            found = _find_authz_denied_response(chained, seen)
            if found is not None:
                return found

    return None


def _raise_if_authz_denied(
    exc: BaseException,
    request_id: str,
    tool_name: str | None,
) -> None:
    response = _find_authz_denied_response(exc)
    if response is None:
        return
    reason = response.headers.get(AUTHZ_REASON_HEADER, "forbidden")
    log_event(
        LOGGER,
        "mcp_authz_denied",
        level=logging.WARNING,
        message=f"MCP request denied by ext_authz: {reason}",
        request_id=request_id,
        tool_name=tool_name,
        authz_reason=reason,
    )
    raise AppError(status_code=403, error="forbidden", message=reason) from exc


def _import_multi_server_client():
    try:
        from langchain_mcp_adapters.client import MultiServerMCPClient
    except ImportError as exc:  # pragma: no cover - dep is required in prod
        raise RuntimeError(
            "langchain-mcp-adapters is required to load MCP tools. "
            "Install it via `uv sync`."
        ) from exc
    return MultiServerMCPClient


async def fetch_mcp_tools(
    user_mcp_url: str,
    obo_token: str | None,
    request_id: str,
) -> list[Any]:
    """Build a fresh MCP client whose streamable-HTTP requests carry the
    given OBO bearer (if any) and the caller's X-Request-ID, then return
    the LangChain tool wrappers.

    A fresh client per request avoids cross-thread ContextVar propagation
    problems when LangChain's sync `tool.invoke()` bridges into the
    adapter's async transport.
    """
    MultiServerMCPClient = _import_multi_server_client()

    headers = _base_headers(request_id)
    if obo_token:
        headers["Authorization"] = f"Bearer {obo_token}"

    client = MultiServerMCPClient(
        {
            "user-mcp": {
                "url": user_mcp_url,
                "transport": "streamable_http",
                "headers": headers,
            }
        }
    )
    tools = await client.get_tools()
    for tool in tools:
        tool_name = getattr(tool, "name", None)
        log_event(
            LOGGER,
            "mcp_tool_loaded",
            message=f"Loaded MCP tool {tool_name}",
            request_id=request_id,
            user_mcp_url=user_mcp_url,
            authorization_present=bool(obo_token),
            tool_name=tool_name,
        )
    return list(tools)


def extract_required_scopes(template_tool: Any) -> list[str]:
    """Read `_meta.required_scopes` from a langchain-mcp-adapters tool.

    The adapter places the upstream MCP `_meta` field under the LangChain
    tool's `metadata["_meta"]` (see langchain_mcp_adapters.tools._convert_call_tool_result).
    Returns an empty list if the tool didn't declare any scope contract.
    """
    metadata = getattr(template_tool, "metadata", None) or {}
    if not isinstance(metadata, dict):
        return []
    meta = metadata.get("_meta") or {}
    if not isinstance(meta, dict):
        return []
    scopes = meta.get("required_scopes")
    if isinstance(scopes, list):
        return [str(s) for s in scopes]
    return []


async def invoke_mcp_tool(
    user_mcp_url: str,
    tool_name: str,
    args: dict,
    obo_token: str,
    request_id: str,
) -> Any:
    """Build a transient MCP client carrying *obo_token* and call a single
    tool by name. Used by the per-call scope wrapper so each MCP tools/call
    travels with its own narrowly-scoped OBO."""
    MultiServerMCPClient = _import_multi_server_client()

    headers = _base_headers(request_id)
    headers["Authorization"] = f"Bearer {obo_token}"
    client = MultiServerMCPClient(
        {
            "user-mcp": {
                "url": user_mcp_url,
                "transport": "streamable_http",
                "headers": headers,
            }
        }
    )
    try:
        tools = await client.get_tools()
        target = next(
            (t for t in tools if getattr(t, "name", None) == tool_name), None
        )
        if target is None:
            raise RuntimeError(
                f"MCP tool {tool_name!r} not found at {user_mcp_url}"
            )
        return await target.ainvoke(args)
    except AppError:
        raise
    except BaseException as exc:
        _raise_if_authz_denied(exc, request_id=request_id, tool_name=tool_name)
        raise


