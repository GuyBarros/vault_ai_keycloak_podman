from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
#------------

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from langchain.chat_models import init_chat_model
from prometheus_fastapi_instrumentator import Instrumentator

from agent_runtime import AgentRuntime
from config import Settings, load_settings
from errors import AppError
from identity import OboTokenService
from logging_utils import (
    bind_log_context,
    build_uvicorn_log_config,
    log_event,
    reset_log_context,
)
from mcp_client import extract_required_scopes, fetch_mcp_tools
from models import AgentTokensResponse, ChatRequest
from pii_masking import make_mask_pii_tool
from scoped_tool import make_scoped_tool
from security import (
    extract_agent_identity_claims,
    extract_bearer_token,
    extract_user_groups,
    extract_user_identity_claims,
    validate_access_token,
)
from tools import TOOLS as LOCAL_TOOLS

SETTINGS = load_settings()
LOGGER = logging.getLogger("agent_api")


def _get_client_ip(request: Request) -> str | None:
    return request.client.host if request.client is not None else None


def _build_base_llm(settings: Settings):
    return init_chat_model(settings.model, streaming=True, timeout=120)


def _build_runtime_for_request(
    llm,
    tools: list,
    is_admin: bool = False,
) -> AgentRuntime:
    return AgentRuntime(
        llm_with_tools=llm.bind_tools(tools),
        logger=LOGGER,
        tool_registry={tool.name: tool for tool in tools},
        is_admin=is_admin,
    )


def _error_response(request: Request, status_code: int, error: str, message: str) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)
    log_event(
        LOGGER,
        "request_failed",
        level=logging.ERROR,
        message="Request failed",
        request_id=request_id,
        path=request.url.path,
        status_code=status_code,
        error=error,
        error_message=message,
    )
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "message": message},
    )


async def _discover_mcp_template_tools_at_startup(user_mcp_url: str) -> list:
    """One-shot discovery against user-mcp using no OBO.

    user-mcp must be configured with `USER_MCP_ALLOW_UNAUTH_DISCOVERY=true` for
    this to succeed; the network channel is presumed secured at the mesh layer
    (Consul service-intentions). The returned `_meta.required_scopes` on each
    template drives the per-call scope the agent later exchanges OBO tokens
    for. Failures are swallowed so the service still boots — `query_agent`
    will operate with no MCP tools until discovery succeeds on a restart.
    """
    try:
        templates = await fetch_mcp_tools(user_mcp_url, None, "startup")
    except Exception as exc:  # noqa: BLE001 - startup discovery is best-effort
        log_event(
            LOGGER,
            "mcp_discovery_failed_at_startup",
            level=logging.WARNING,
            message=f"MCP startup discovery failed against {user_mcp_url}: {exc}",
            user_mcp_url=user_mcp_url,
        )
        return []

    log_event(
        LOGGER,
        "mcp_discovery_completed_at_startup",
        message=f"Discovered {len(templates)} MCP tool template(s) at startup",
        user_mcp_url=user_mcp_url,
        tool_count=len(templates),
        tool_names=[getattr(t, "name", None) for t in templates],
    )
    return templates


def _wrap_mcp_tools_with_per_call_obo(
    template_tools: list,
    token_service: OboTokenService,
    subject_token: str | None,
    request_id: str,
    user_mcp_url: str,
    bypass: bool,
) -> list:
    """Replace each MCP tool with a wrapper that exchanges a scope-specific
    OBO right before the upstream call. In bypass mode (no real user), pass
    the templates through unchanged so the dev loop keeps working."""
    if bypass or subject_token is None:
        return template_tools

    wrapped: list = []
    for template in template_tools:
        required_scopes = extract_required_scopes(template)
        if not required_scopes:
            log_event(
                LOGGER,
                "mcp_tool_missing_required_scopes",
                level=logging.WARNING,
                message=(
                    f"MCP tool {getattr(template, 'name', '?')} did not advertise "
                    f"_meta.required_scopes; passing through without per-call OBO."
                ),
                request_id=request_id,
                tool_name=getattr(template, "name", None),
            )
            wrapped.append(template)
            continue
        wrapped.append(
            make_scoped_tool(
                template_tool=template,
                required_scopes=required_scopes,
                token_service=token_service,
                subject_token=subject_token,
                request_id=request_id,
                user_mcp_url=user_mcp_url,
            )
        )
    return wrapped


def _read_vault_token_for_transform(token_service: OboTokenService) -> str:
    """Return the agent's actor token to use as the Vault token for Transform calls.

    The actor token is a Vault token that the agent already has on disk; it is
    the appropriate credential for reaching the Transform secrets engine from
    within the agent process.  If it is unavailable the masking tool will fall
    back to local star-masking for every field.
    """
    try:
        return token_service.read_actor_token()
    except AppError:
        return ""


def _load_startup_agent_id(token_service: OboTokenService) -> str | None:
    try:
        actor_token = token_service.read_actor_token()
    except AppError as exc:
        log_event(
            LOGGER,
            "actor_token_unavailable_at_startup",
            level=logging.WARNING,
            message="Actor token unavailable at startup; agent_id will be omitted from log prefix.",
            error=exc.error,
            error_message=exc.message,
        )
        return None
    return extract_agent_identity_claims(actor_token)["actor_agent_id"]


def create_app(
    settings: Settings | None = None,
    runtime: AgentRuntime | None = None,
    token_service: OboTokenService | None = None,
    llm: object | None = None,
) -> FastAPI:
    active_settings = settings or SETTINGS

    @asynccontextmanager
    async def lifespan(app_inner: FastAPI):
        app_inner.state.mcp_template_tools = await _discover_mcp_template_tools_at_startup(
            active_settings.user_mcp_url
        )
        yield

    app = FastAPI(lifespan=lifespan)
    Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)
    app.state.settings = active_settings
    app.state.llm = llm or _build_base_llm(active_settings)
    # When set (in tests), this fixed runtime is used instead of building one
    # per request. In production it stays None and the route reuses the
    # startup-discovered MCP tool templates, wrapping them per request with
    # tool-specific OBO tokens.
    app.state.agent_runtime = runtime
    # Populated by the lifespan handler at startup. Kept as an empty list so
    # the route is callable even before lifespan runs (test contexts).
    app.state.mcp_template_tools = []
    app.state.token_service = token_service or OboTokenService(
        settings=active_settings,
        logger=LOGGER,
    )
    app.state.actor_agent_id = _load_startup_agent_id(app.state.token_service)

    @app.middleware("http")
    async def request_logging_middleware(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        request.state.client_ip = _get_client_ip(request)
        context_token = bind_log_context(
            request_id=request_id,
            path=request.url.path,
            http_method=request.method,
            client_ip=request.state.client_ip,
            actor_agent_id=request.app.state.actor_agent_id,
        )
        try:
            log_event(
                LOGGER,
                "request_received",
                level=logging.DEBUG,
                message="Request received",
                request_id=request_id,
                path=request.url.path,
                method=request.method,
            )
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            if request.url.path != "/v1/agent/query" and not isinstance(
                response, StreamingResponse
            ):
                log_event(
                    LOGGER,
                    "response_sent",
                    level=logging.DEBUG,
                    message="Response sent",
                    request_id=request_id,
                    path=request.url.path,
                    status_code=response.status_code,
                )
            return response
        finally:
            reset_log_context(context_token)

    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        return _error_response(request, exc.status_code, exc.error, exc.message)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return _error_response(
            request,
            status_code=400,
            error="invalid_request",
            message=str(exc),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        return _error_response(
            request,
            status_code=500,
            error="agent_error",
            message="Agent execution failed.",
        )

    @app.post("/v1/agent/query")
    async def query_agent(request: Request, chat_request: ChatRequest):
        access_token: str | None = None
        preferred_username: str | None = None
        is_admin: bool = False
        if not request.app.state.settings.bypass_auth_token_exchange:
            access_token = extract_bearer_token(request)
            access_token_payload = validate_access_token(access_token)
            preferred_username = extract_user_identity_claims(
                access_token_payload
            )["preferred_username"]
            user_groups = extract_user_groups(access_token_payload)
            is_admin = "admins" in user_groups
            log_event(
                LOGGER,
                "user_group_check",
                level=logging.DEBUG,
                message="Evaluated user group membership for PII policy",
                request_id=request.state.request_id,
                preferred_username=preferred_username,
                groups=user_groups,
                is_admin=is_admin,
            )
        bind_log_context(preferred_username=preferred_username)

        runtime = request.app.state.agent_runtime
        if runtime is None:
            scoped_tools = _wrap_mcp_tools_with_per_call_obo(
                template_tools=request.app.state.mcp_template_tools,
                token_service=request.app.state.token_service,
                subject_token=access_token,
                request_id=request.state.request_id,
                user_mcp_url=request.app.state.settings.user_mcp_url,
                bypass=request.app.state.settings.bypass_auth_token_exchange,
            )
            # Build the mask_pii tool.  The Vault token is the agent's own
            # actor token so it can reach the Transform secrets engine without
            # requiring a per-user OBO for this internal operation.
            vault_token = _read_vault_token_for_transform(request.app.state.token_service)
            mask_pii_tool = make_mask_pii_tool(
                vault_transform_url=request.app.state.settings.vault_transform_url,
                vault_token=vault_token,
                vault_role=request.app.state.settings.vault_transform_role,
            )
            tools = list(LOCAL_TOOLS) + scoped_tools + [mask_pii_tool]
            runtime = _build_runtime_for_request(request.app.state.llm, tools, is_admin=is_admin)

        return await runtime.handle_request(
            chat_request=chat_request,
            request_id=request.state.request_id,
            request_path=request.url.path,
            request_method=request.method,
            client_ip=request.state.client_ip,
        )

    @app.get("/v1/agent/tokens", response_model=AgentTokensResponse)
    async def get_cached_tokens(request: Request) -> AgentTokensResponse:
        # actor_token is independent of OBO exchange and is always available.
        # The OBO returned here is the most recently exchanged one for this
        # subject — when a turn issues multiple scoped OBOs (read then write),
        # the inspector reflects whichever was last requested.
        actor_token = request.app.state.token_service.read_actor_token()

        if request.app.state.settings.bypass_auth_token_exchange:
            return AgentTokensResponse(actor_token=actor_token, obo_token=None)

        access_token = extract_bearer_token(request)
        validate_access_token(access_token)
        obo_token = request.app.state.token_service.get_last_obo_token(access_token)
        return AgentTokensResponse(actor_token=actor_token, obo_token=obo_token)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=SETTINGS.host,
        port=SETTINGS.port,
        log_level=SETTINGS.log_level.lower(),
        log_config=build_uvicorn_log_config(SETTINGS.log_level),
    )
