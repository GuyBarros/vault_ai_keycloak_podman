from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastmcp import FastMCP

from auth.scope_check import configure_bypass
from config import Settings
from logging_utils import log_event
from storage import build_repository
from storage.base import UserRepository
from tools import register_tools

LOGGER = logging.getLogger("user_mcp.mcp_app")


def build_mcp_app(settings: Settings) -> tuple[FastMCP, UserRepository]:
    """Construct the FastMCP server, the storage repository, and register the
    user-management tools. Returns the FastMCP instance plus the repo so the
    ASGI entrypoint can drive lifespan startup/shutdown around it."""

    configure_bypass(settings.bypass_auth)
    repo = build_repository(settings)

    @asynccontextmanager
    async def lifespan(_server: FastMCP):
        log_event(
            LOGGER,
            "mcp_server_starting",
            message="Starting user-mcp server",
            user_backend=settings.user_backend,
        )
        await repo.startup()
        try:
            yield {"repo": repo}
        finally:
            log_event(
                LOGGER,
                "mcp_server_stopping",
                message="Stopping user-mcp server",
            )
            await repo.shutdown()

    mcp = FastMCP(name="user-mcp", lifespan=lifespan)
    register_tools(mcp, repo)
    return mcp, repo
