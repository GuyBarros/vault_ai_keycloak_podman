from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from spiffe import WorkloadApiClient
from spiffe.errors import ArgumentError
from spiffe.workloadapi.errors import FetchJwtSvidError

from errors import AppError
from logging_utils import log_event

LOGGER = logging.getLogger("user_mcp.spiffe")

# JWT-SVID TTL in this deployment's SPIRE registration entries is 300s
# (docker-compose/templates/spire/spire-setup.sh); refresh with headroom so a
# request never races an about-to-expire SVID.
_REFRESH_HEADROOM_SECONDS = 30.0


@dataclass(frozen=True)
class WorkloadJwtSvid:
    token: str
    spiffe_id: str


class SpiffeSvidProvider:
    """Fetches and caches a SPIFFE JWT-SVID for this workload from the local
    SPIRE Workload API, for use as Vault JWT-auth login material.

    The Workload API client is synchronous gRPC, so fetches run in a worker
    thread to avoid blocking the event loop.
    """

    def __init__(self, socket_path: str, audience: str):
        if not socket_path:
            raise AppError(
                500,
                "configuration_error",
                "USER_MCP_SPIFFE_SOCKET is required when USER_MCP_DB_AUTH_MODE=vault.",
            )
        if not audience:
            raise AppError(
                500,
                "configuration_error",
                "USER_MCP_SPIFFE_JWT_AUDIENCE is required when USER_MCP_DB_AUTH_MODE=vault.",
            )
        self._socket_uri = socket_path if "://" in socket_path else f"unix://{socket_path}"
        self._audience = audience
        self._lock = asyncio.Lock()
        self._cached: WorkloadJwtSvid | None = None
        self._expiry = 0.0

    async def get_jwt_svid(self) -> WorkloadJwtSvid:
        async with self._lock:
            if self._cached is None or time.time() >= self._expiry - _REFRESH_HEADROOM_SECONDS:
                await self._refresh()
            assert self._cached is not None
            return self._cached

    async def _refresh(self) -> None:
        try:
            token, spiffe_id, expiry = await asyncio.to_thread(self._fetch)
        except (ArgumentError, FetchJwtSvidError) as exc:
            raise AppError(
                502,
                "agent_error",
                f"Failed to fetch SPIFFE JWT-SVID from the Workload API: {exc}",
            ) from exc

        self._cached = WorkloadJwtSvid(token=token, spiffe_id=spiffe_id)
        self._expiry = expiry
        log_event(
            LOGGER,
            "spiffe_jwt_svid_fetched",
            level=logging.DEBUG,
            message="Fetched SPIFFE JWT-SVID",
            workload_spiffe_id=spiffe_id,
            audience=self._audience,
            expiry=expiry,
        )

    def _fetch(self) -> tuple[str, str, float]:
        with WorkloadApiClient(socket_path=self._socket_uri) as client:
            svid = client.fetch_jwt_svid(audience={self._audience})
        return svid.token, str(svid.spiffe_id), float(svid.expiry)
