from __future__ import annotations

"""PII masking tool for the AI agent.

When the agent returns user records to a non-admin caller it must call
``mask_pii`` on the raw JSON string before presenting it to the user.

Masking strategy
----------------
Fields sent to Vault Transform (``/v1/transform/encode/<role>``) for
format-preserving masking:

* ``ssn``               → transformation ``mask-ssn``
* ``credit_card_number``→ transformation ``mask-credit-card``
  (Vault's builtin template requires digits only; dashes are stripped)

All other PII fields are masked locally — no Vault round-trip:

* ``email``      → ``***@<domain>``
* ``phone``      → every digit replaced with ``*``
* ``ip_address`` → every digit replaced with ``*``
"""

import json
import logging
import re
from typing import Any

import httpx
from langchain_core.tools import tool

from logging_utils import log_event

LOGGER = logging.getLogger("agent_api.pii_masking")

# PII field names that carry sensitive values in a UserRecord.
_PII_FIELDS: frozenset[str] = frozenset(
    {"ssn", "credit_card_number", "email", "phone", "ip_address"}
)

# Fields routed to Vault Transform and the transformation name to use.
_VAULT_TRANSFORMATIONS: dict[str, str] = {
    "ssn": "mask-ssn",
    "credit_card_number": "mask-credit-card",
}


# ---------------------------------------------------------------------------
# Local (Python) maskers
# ---------------------------------------------------------------------------

def _mask_email(value: str) -> str:
    at = value.find("@")
    if at <= 0:
        return "***"
    return "***@" + value[at + 1:]


def _mask_phone(value: str) -> str:
    return re.sub(r"\d", "*", value)


def _mask_ip(value: str) -> str:
    return re.sub(r"\d", "*", value)


_LOCAL_MASKERS = {
    "email": _mask_email,
    "phone": _mask_phone,
    "ip_address": _mask_ip,
}


def _normalize_cc(value: str) -> str:
    """Strip non-digit chars so the value matches ``builtin/creditcardnumber``."""
    return re.sub(r"\D", "", value)


def _already_masked(value: str) -> bool:
    """Skip Vault when MCP (or a prior pass) already star-masked the field."""
    return "*" in value


def _vault_ready_value(field: str, raw: str) -> str | None:
    """Return a Transform-eligible value, or None to skip the Vault call."""
    if _already_masked(raw):
        return None
    if field == "credit_card_number":
        digits = _normalize_cc(raw)
        return digits if 13 <= len(digits) <= 19 else None
    if field == "ssn":
        digits = re.sub(r"\D", "", raw)
        return raw if len(digits) == 9 else None
    return raw or None


# ---------------------------------------------------------------------------
# Vault Transform helper
# ---------------------------------------------------------------------------

async def _vault_encode(
    vault_transform_url: str,
    vault_token: str,
    role: str,
    transformation: str,
    value: str,
) -> str:
    """Call ``POST /v1/transform/encode/<role>`` and return the masked value."""
    url = f"{vault_transform_url.rstrip('/')}/encode/{role}"
    payload = {"transformation": transformation, "value": value}
    headers = {
        "X-Vault-Token": vault_token,
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
    return str(data["data"]["encoded_value"])


# ---------------------------------------------------------------------------
# Record-level masker (used by the LangChain tool below)
# ---------------------------------------------------------------------------

async def _mask_record(
    record: dict[str, Any],
    vault_transform_url: str,
    vault_token: str,
    vault_role: str,
) -> dict[str, Any]:
    """Return a copy of *record* with all PII fields masked."""
    result = dict(record)

    # Vault Transform fields
    for field, transformation in _VAULT_TRANSFORMATIONS.items():
        raw = result.get(field)
        if raw is None:
            continue
        value = _vault_ready_value(field, str(raw))
        if value is None:
            continue
        try:
            masked = await _vault_encode(
                vault_transform_url=vault_transform_url,
                vault_token=vault_token,
                role=vault_role,
                transformation=transformation,
                value=value,
            )
            result[field] = masked
        except Exception as exc:  # noqa: BLE001
            log_event(
                LOGGER,
                "pii_vault_mask_failed",
                level=logging.WARNING,
                message=f"Vault Transform masking failed for field {field}: {exc}",
                field=field,
            )
            # Fall back to local star-masking so PII is never returned unmasked.
            result[field] = re.sub(r"[0-9A-Za-z]", "*", str(raw))

    # Local maskers
    for field, masker in _LOCAL_MASKERS.items():
        raw = result.get(field)
        if raw is not None:
            result[field] = masker(str(raw))

    return result


# ---------------------------------------------------------------------------
# Factory — returns a bound LangChain tool
# ---------------------------------------------------------------------------

def make_mask_pii_tool(
    vault_transform_url: str,
    vault_token: str,
    vault_role: str,
) -> Any:
    """Return a LangChain ``@tool`` with Vault credentials closed over.

    The returned tool accepts a JSON string (a single UserRecord dict or a list
    of UserRecord dicts) and returns the same structure with all PII fields
    masked.  The agent should call it whenever it receives user data that must
    be presented to a non-admin caller.
    """

    @tool
    async def mask_pii(user_data_json: str) -> str:
        """Mask all PII fields in one or more user records.

        Accepts a JSON-encoded UserRecord object or a JSON array of UserRecord
        objects.  Returns the same structure (single object or array) as a JSON
        string with every PII field (ssn, credit_card_number, email, phone,
        ip_address) replaced by a masked value.

        Call this tool whenever you are about to display user records to a
        caller who is NOT in the 'admin' group.  Do not display raw user records
        to non-admin callers without masking first.
        """
        try:
            parsed = json.loads(user_data_json)
        except json.JSONDecodeError as exc:
            return f"mask_pii error: input is not valid JSON — {exc}"

        is_list = isinstance(parsed, list)
        records: list[dict[str, Any]] = parsed if is_list else [parsed]

        masked_records: list[dict[str, Any]] = []
        for record in records:
            if not isinstance(record, dict):
                masked_records.append(record)
                continue
            masked = await _mask_record(
                record=record,
                vault_transform_url=vault_transform_url,
                vault_token=vault_token,
                vault_role=vault_role,
            )
            masked_records.append(masked)

        log_event(
            LOGGER,
            "pii_masked",
            message=f"Masked PII for {len(masked_records)} record(s)",
            record_count=len(masked_records),
        )

        result = masked_records if is_list else masked_records[0]
        return json.dumps(result, default=str)

    return mask_pii
