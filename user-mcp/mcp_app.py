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
from vault_client import VaultClient
from vault_transform import TransformMasker
from spiffe_client import SpiffeSvidProvider

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

    masker = None
    if (
        settings.transform_enabled
        and settings.db_auth_mode == "vault"
        and settings.transform_role
        and settings.spiffe_socket
    ):
        vault_tls_verify: bool | str = (
            settings.vault_ca_bundle.strip() or settings.vault_verify_tls
        )
        masker = TransformMasker(
            vault=VaultClient(
                addr=settings.vault_addr,
                jwt_path=settings.vault_spiffe_jwt_path,
                namespace=settings.vault_namespace or None,
                verify_tls=vault_tls_verify,
                timeout_seconds=settings.vault_request_timeout_seconds,
            ),
            spiffe=SpiffeSvidProvider(
                socket_path=settings.spiffe_socket,
                audience=settings.spiffe_jwt_audience,
            ),
            jwt_role=settings.vault_spiffe_transform_role,
            transform_role=settings.transform_role,
        )

    mcp = FastMCP(name="user-mcp", lifespan=lifespan)
    register_tools(mcp, repo, masker=masker)
    return mcp, repo
