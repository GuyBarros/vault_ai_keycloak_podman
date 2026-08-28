from __future__ import annotations

import hashlib
import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any

from config import Settings
from errors import AppError
from logging_utils import log_event
from security import decode_jwt_payload


@dataclass
class CachedToken:
    token: str
    expiry_time: float


def read_actor_token(actor_token_path: Path, logger: logging.Logger) -> str:
    log_event(
        logger,
        "actor_token_path_used",
        level=logging.DEBUG,
        message="Reading actor token from configured path",
        actor_token_path=str(actor_token_path),
    )

    if not actor_token_path.exists():
        raise AppError(
            status_code=500,
            error="agent_error",
            message=f"Actor token file not found at {actor_token_path}",
        )

    actor_token = actor_token_path.read_text(encoding="utf-8").strip()
    if not actor_token:
        raise AppError(
            status_code=500,
            error="agent_error",
            message="Actor token file is empty.",
        )

    return actor_token


def normalize_scopes(scopes: list[str] | tuple[str, ...] | None) -> str:
    """Return *scopes* as a deduped, sorted, single-space-joined string.

    Stable across orderings so cache keys don't fragment when the same scope
    set is requested in different orders.
    """
    if not scopes:
        return ""
    return " ".join(sorted({s for s in scopes if s}))


def build_cache_key(subject_token: str, role_name: str, normalized_scope: str = "") -> str:
    return hashlib.sha256(
        f"{subject_token}:{role_name}:{normalized_scope}".encode("utf-8")
    ).hexdigest()


def _coerce_expiry_timestamp(raw_value: Any, field_name: str) -> float:
    if isinstance(raw_value, (int, float)):
        return float(raw_value)

    if isinstance(raw_value, str) and raw_value.strip():
        trimmed_value = raw_value.strip()
        try:
            return float(trimmed_value)
        except ValueError:
            try:
                return datetime.fromisoformat(trimmed_value.replace("Z", "+00:00")).timestamp()
            except ValueError as exc:
                raise AppError(
                    status_code=502,
                    error="token_exchange_failed",
                    message=f"Token exchange response contained an invalid {field_name}.",
                ) from exc

    raise AppError(
        status_code=502,
        error="token_exchange_failed",
        message=f"Token exchange response contained an invalid {field_name}.",
    )


def extract_obo_token_details(response_payload: Any) -> tuple[str, float]:
    if not isinstance(response_payload, dict):
        raise AppError(
            status_code=502,
            error="token_exchange_failed",
            message="Token exchange response must be a JSON object.",
        )

    obo_token = ""
    for token_field in ("obo_token", "access_token", "token"):
        candidate = response_payload.get(token_field)
        if isinstance(candidate, str) and candidate.strip():
            obo_token = candidate.strip()
            break

    if not obo_token:
        raise AppError(
            status_code=502,
            error="token_exchange_failed",
            message="Token exchange response did not include an OBO token.",
        )

    if "expiry_time" in response_payload:
        expiry_time = _coerce_expiry_timestamp(
            response_payload["expiry_time"], "expiry_time"
        )
    elif "expires_at" in response_payload:
        expiry_time = _coerce_expiry_timestamp(
            response_payload["expires_at"], "expires_at"
        )
    elif "expires_in" in response_payload:
        expires_in = response_payload["expires_in"]
        if not isinstance(expires_in, (int, float, str)):
            raise AppError(
                status_code=502,
                error="token_exchange_failed",
                message="Token exchange response contained an invalid expires_in.",
            )
        expiry_time = time.time() + float(expires_in)
    else:
        obo_payload = decode_jwt_payload(obo_token, "OBO token")
        exp = obo_payload.get("exp")
        if not isinstance(exp, (int, float)):
            raise AppError(
                status_code=502,
                error="token_exchange_failed",
                message="Token exchange response did not include token expiry information.",
            )
        expiry_time = float(exp)

    if expiry_time <= time.time():
        raise AppError(
            status_code=502,
            error="token_exchange_failed",
            message="Token exchange returned an expired OBO token.",
        )

    return obo_token, expiry_time


def perform_token_exchange(
    subject_token: str,
    actor_token: str,
    settings: Settings,
    logger: logging.Logger,
    request_id: str,
    scope: str,
) -> tuple[str, float]:
    log_event(
        logger,
        "identity_broker_call",
        message="Calling identity broker for OBO token exchange",
        request_id=request_id,
        token_exchange_url=settings.token_exchange_url,
        scope=scope,
    )
    payload = json.dumps(
        {
            "subject_token": subject_token,
            "actor_token": actor_token,
            "scope": scope,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        settings.token_exchange_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Request-ID": request_id,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request, timeout=settings.token_exchange_timeout_seconds
        ) as response:
            response_body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise AppError(
            status_code=502,
            error="token_exchange_failed",
            message="Failed to obtain OBO token.",
        ) from exc
    except urllib.error.URLError as exc:
        raise AppError(
            status_code=502,
            error="token_exchange_failed",
            message="Failed to obtain OBO token.",
        ) from exc

    try:
        response_payload = json.loads(response_body)
    except json.JSONDecodeError as exc:
        raise AppError(
            status_code=502,
            error="token_exchange_failed",
            message="Token exchange response was not valid JSON.",
        ) from exc

    obo_token, expiry_time = extract_obo_token_details(response_payload)
    log_event(
        logger,
        "obo_token_exchange_completed",
        message="OBO token exchange completed",
        request_id=request_id,
        expiry_time=expiry_time,
        obo_token_present=True,
    )
    return obo_token, expiry_time


class OboTokenService:
    def __init__(self, settings: Settings, logger: logging.Logger):
        self.settings = settings
        self.logger = logger
        self.cache: dict[str, CachedToken] = {}
        # Maps subject_token to the cache_key of its most recent successful
        # exchange. Used by /v1/agent/tokens to surface the latest OBO regardless
        # of scope — a subject that just exchanged users.write should see that
        # token, not whichever scope was cached first.
        self.last_cache_key_by_subject: dict[str, str] = {}
        self.lock = Lock()

    def clear_cache(self) -> None:
        self.cache.clear()
        self.last_cache_key_by_subject.clear()

    def _get_cached_token(self, cache_key: str) -> CachedToken | None:
        cached_value = self.cache.get(cache_key)
        if cached_value is None:
            return None

        if not isinstance(cached_value, CachedToken):
            raise AppError(
                status_code=500,
                error="cache_error",
                message="OBO token cache is corrupted.",
            )

        if not isinstance(cached_value.token, str) or not isinstance(
            cached_value.expiry_time, (int, float)
        ):
            raise AppError(
                status_code=500,
                error="cache_error",
                message="OBO token cache is corrupted.",
            )

        if float(cached_value.expiry_time) <= time.time():
            del self.cache[cache_key]
            return None

        return cached_value

    def perform_token_exchange(
        self,
        subject_token: str,
        actor_token: str,
        request_id: str,
        scope: str,
    ) -> tuple[str, float]:
        return perform_token_exchange(
            subject_token=subject_token,
            actor_token=actor_token,
            settings=self.settings,
            logger=self.logger,
            request_id=request_id,
            scope=scope,
        )

    def get_cached_token(
        self,
        subject_token: str,
        request_id: str,
        scopes: list[str] | None = None,
    ) -> str:
        normalized_scope = normalize_scopes(scopes)
        cache_key = build_cache_key(
            subject_token, self.settings.obo_role_name, normalized_scope
        )

        with self.lock:
            cached_entry = self._get_cached_token(cache_key)
            if cached_entry is None:
                log_event(
                    self.logger,
                    "token_cache_miss",
                    level=logging.DEBUG,
                    message="OBO token cache miss",
                    request_id=request_id,
                    cache_key=cache_key,
                    scope=normalized_scope,
                )
                raise AppError(
                    status_code=404,
                    error="token_not_found",
                    message="No cached OBO token found for the provided bearer token.",
                )

            log_event(
                self.logger,
                "token_cache_hit",
                level=logging.DEBUG,
                message="OBO token cache hit",
                request_id=request_id,
                cache_key=cache_key,
                scope=normalized_scope,
                expiry_time=cached_entry.expiry_time,
                obo_token_present=True,
            )
            return cached_entry.token

    def read_actor_token(self) -> str:
        return read_actor_token(self.settings.actor_token_path, self.logger)

    def resolve_token(
        self,
        subject_token: str,
        request_id: str,
        scopes: list[str],
    ) -> str:
        """Return an OBO token for *subject_token* carrying exactly *scopes*.

        Cache key is (subject_token, role_name, normalized_scope) so different
        scope sets never share an entry — the token returned to a caller asking
        for `users.read` will never accidentally grant `users.write`.
        """
        if not scopes:
            raise AppError(
                status_code=500,
                error="agent_error",
                message="resolve_token requires a non-empty scopes list.",
            )

        normalized_scope = normalize_scopes(scopes)
        cache_key = build_cache_key(
            subject_token, self.settings.obo_role_name, normalized_scope
        )

        with self.lock:
            cached_entry = self._get_cached_token(cache_key)
            if cached_entry is not None:
                log_event(
                    self.logger,
                    "token_cache_hit",
                    level=logging.DEBUG,
                    message="OBO token cache hit",
                    request_id=request_id,
                    cache_key=cache_key,
                    scope=normalized_scope,
                    expiry_time=cached_entry.expiry_time,
                    obo_token_present=True,
                )
                self.last_cache_key_by_subject[subject_token] = cache_key
                return cached_entry.token

            log_event(
                self.logger,
                "token_cache_miss",
                level=logging.DEBUG,
                message="OBO token cache miss",
                request_id=request_id,
                cache_key=cache_key,
                scope=normalized_scope,
            )
            actor_token = read_actor_token(self.settings.actor_token_path, self.logger)
            obo_token, expiry_time = self.perform_token_exchange(
                subject_token=subject_token,
                actor_token=actor_token,
                request_id=request_id,
                scope=normalized_scope,
            )
            self.cache[cache_key] = CachedToken(
                token=obo_token,
                expiry_time=expiry_time,
            )
            self.last_cache_key_by_subject[subject_token] = cache_key
            return obo_token

    def get_last_obo_token(self, subject_token: str) -> str | None:
        """Return the most recently exchanged OBO token for *subject_token*.

        Returns ``None`` when no exchange has occurred for this subject, or when
        the most recent entry has expired/been evicted from the cache.
        """
        with self.lock:
            cache_key = self.last_cache_key_by_subject.get(subject_token)
            if cache_key is None:
                return None
            cached_entry = self._get_cached_token(cache_key)
            if cached_entry is None:
                self.last_cache_key_by_subject.pop(subject_token, None)
                return None
            return cached_entry.token
