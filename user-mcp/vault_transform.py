from __future__ import annotations

"""PII masking for UserRecord responses.

Strategy
--------
Vault Transform's ``masking`` type only works reliably with its two builtin
templates in this deployment:

* ``builtin/socialsecuritynumber``  →  transformation ``mask-ssn``
* ``builtin/creditcardnumber``      →  transformation ``mask-credit-card``
  (requires digits-only input; the credit_card_number field stores values like
  ``NNNN-NNNN-NNNN-NNNN`` so dashes are stripped before encoding)

All other PII fields (email, phone, ip_address) are masked locally in Python —
no Vault round-trip, no regex compatibility issues.

Public API
----------
* :func:`mask_user_record`  — mask a single :class:`~models.UserRecord`
* :func:`mask_user_records` — mask a list concurrently
"""

import asyncio
import logging
import re

from logging_utils import log_event
from models import UserRecord
from vault_client import VaultClient

LOGGER = logging.getLogger("user_mcp.vault_transform")

# Fields delegated to Vault Transform and their transformation names.
# The builtin/creditcardnumber template requires digits only — see
# _normalize_cc() below.
_VAULT_TRANSFORMATIONS: dict[str, str] = {
    "ssn": "mask-ssn",
    "credit_card_number": "mask-credit-card",
}


# ---------------------------------------------------------------------------
# Local (Python) maskers — no Vault call needed
# ---------------------------------------------------------------------------

def _mask_email(value: str) -> str:
    """Keep the domain, replace the local part with stars.

    ``alice.smith@example.com`` → ``***@example.com``
    """
    at = value.find("@")
    if at <= 0:
        return "***"
    return "***@" + value[at + 1:]


def _mask_phone(value: str) -> str:
    """Replace every digit with ``*``, preserve non-digit formatting chars."""
    return re.sub(r"\d", "*", value)


def _mask_ip(value: str) -> str:
    """Replace every digit with ``*``, preserve dots."""
    return re.sub(r"\d", "*", value)


# Maps field name → local masker for fields not sent to Vault.
_LOCAL_MASKERS = {
    "email": _mask_email,
    "phone": _mask_phone,
    "ip_address": _mask_ip,
}


# ---------------------------------------------------------------------------
# Credit-card normalisation
# ---------------------------------------------------------------------------

def _normalize_cc(value: str) -> str:
    """Strip all non-digit characters so the value matches
    ``builtin/creditcardnumber`` (digits only, 13–19 chars).
    """
    return re.sub(r"\D", "", value)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def mask_user_record(
    record: UserRecord,
    vault: VaultClient,
    client_token: str,
    transform_role: str,
) -> UserRecord:
    """Return a copy of *record* with all PII fields masked.

    SSN and credit_card_number are masked via Vault Transform.
    email, phone, and ip_address are masked locally in Python.
    Fields with a ``None`` value are left unchanged.
    """
    raw = record.model_dump(mode="python")

    # ── Vault Transform fields (concurrent) ──────────────────────────────────
    vault_fields = {
        field: transformation
        for field, transformation in _VAULT_TRANSFORMATIONS.items()
        if raw.get(field) is not None
    }

    async def _encode(field: str, transformation: str) -> tuple[str, str]:
        value = str(raw[field])
        # Normalise credit card to digits-only for the builtin template.
        if field == "credit_card_number":
            value = _normalize_cc(value)
        masked = await vault.transform_encode(
            client_token=client_token,
            role=transform_role,
            transformation=transformation,
            value=value,
        )
        return field, masked

    vault_results: dict[str, str] = {}
    if vault_fields:
        pairs = await asyncio.gather(
            *(_encode(f, t) for f, t in vault_fields.items()),
            return_exceptions=False,
        )
        vault_results = dict(pairs)

    # ── Local maskers ─────────────────────────────────────────────────────────
    local_results: dict[str, str] = {}
    for field, masker in _LOCAL_MASKERS.items():
        if raw.get(field) is not None:
            local_results[field] = masker(str(raw[field]))

    masked_fields = {**vault_results, **local_results}
    if masked_fields:
        log_event(
            LOGGER,
            "pii_masked",
            level=logging.DEBUG,
            message="PII fields masked for user record",
            vault_masked=sorted(vault_results.keys()),
            local_masked=sorted(local_results.keys()),
        )

    updated = {**raw, **masked_fields}
    return UserRecord.model_validate(updated)


async def mask_user_records(
    records: list[UserRecord],
    vault: VaultClient,
    client_token: str,
    transform_role: str,
) -> list[UserRecord]:
    """Mask every record in *records* concurrently."""
    if not records:
        return records
    masked = await asyncio.gather(
        *(
            mask_user_record(r, vault, client_token, transform_role)
            for r in records
        ),
        return_exceptions=False,
    )
    return list(masked)


class TransformMasker:
    """Masks UserRecord tool results via Vault Transform using this workload's SPIFFE identity."""

    def __init__(
        self,
        vault: VaultClient,
        spiffe,
        jwt_role: str,
        transform_role: str,
    ):
        self._vault = vault
        self._spiffe = spiffe
        self._jwt_role = jwt_role
        self._transform_role = transform_role

    async def mask_result(self, result):
        """Mask a UserRecord or list[UserRecord]; other values pass through."""
        svid = await self._spiffe.get_jwt_svid()
        client_token = await self._vault.login_with_jwt(svid.token, self._jwt_role)
        if isinstance(result, list) and result and isinstance(result[0], UserRecord):
            masked = await mask_user_records(
                result, self._vault, client_token, self._transform_role
            )
            log_event(
                LOGGER,
                "pii_masked",
                message=f"Vault Transform masked {len(masked)} user record(s)",
                record_count=len(masked),
                transform_role=self._transform_role,
            )
            return masked
        if isinstance(result, UserRecord):
            masked = await mask_user_record(
                result, self._vault, client_token, self._transform_role
            )
            log_event(
                LOGGER,
                "pii_masked",
                message="Vault Transform masked 1 user record",
                record_count=1,
                transform_role=self._transform_role,
            )
            return masked
        return result
