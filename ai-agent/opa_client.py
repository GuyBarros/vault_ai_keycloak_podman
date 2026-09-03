from __future__ import annotations

import base64
import logging
from typing import Any

import httpx

from errors import AppError
from logging_utils import log_event

LOGGER = logging.getLogger("agent_api.opa")


class OpaClient:
    """Query the in-cluster OPA server with the demo Rego bundles.

    The shipped policies decode `input` as a base64 string (prompt or reply).
    """

    def __init__(self, base_url: str, timeout_seconds: float = 5.0):
        self._base = base_url.rstrip("/")
        self._timeout = timeout_seconds

    async def _query(self, data_path: str, text: str) -> Any:
        encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
        url = f"{self._base}/v1/data/{data_path}"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(url, json={"input": encoded})
            response.raise_for_status()
            return response.json().get("result")

    async def deny_if_unsafe_prompt(self, prompt: str) -> None:
        """Raise 403 when prompt-injection or code-safety rules match."""
        try:
            injection = bool(await self._query("app/security/is_injection", prompt))
            unsafe = bool(await self._query("app/security/is_unsafe", prompt))
        except Exception as exc:  # noqa: BLE001
            log_event(
                LOGGER,
                "opa_prompt_check_failed",
                level=logging.WARNING,
                message=f"OPA prompt check failed open: {exc}",
            )
            return
        if injection or unsafe:
            log_event(
                LOGGER,
                "opa_prompt_denied",
                level=logging.WARNING,
                message="OPA blocked prompt",
                is_injection=injection,
                is_unsafe=unsafe,
            )
            raise AppError(
                403,
                "policy_denied",
                "Request blocked by OPA policy (prompt injection or unsafe code).",
            )
        log_event(
            LOGGER,
            "opa_prompt_allowed",
            message="OPA allowed prompt",
        )

    async def sanitize_response(self, text: str) -> str:
        """Apply the PII filter policy to leftover plaintext in the model reply."""
        if not text:
            return text
        try:
            masked = await self._query("app/masking/masked_result", text)
        except Exception as exc:  # noqa: BLE001
            log_event(
                LOGGER,
                "opa_response_filter_failed",
                level=logging.WARNING,
                message=f"OPA response filter failed open: {exc}",
            )
            return text
        if isinstance(masked, str) and masked:
            if masked != text:
                log_event(
                    LOGGER,
                    "opa_response_filtered",
                    message="OPA sanitized agent response",
                )
            return masked
        return text
