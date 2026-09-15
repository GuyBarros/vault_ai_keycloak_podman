from __future__ import annotations

import time
from threading import Lock

_WINDOW_SECONDS = 300
_DENY_LIMIT = 3


class DenyTracker:
    """Count consecutive unauthorized tool outcomes per human subject.

    Three denies inside five minutes raise session_revoked. Keycloak ends the
    SSO session (Admin logout) and emits CAEP session-revoked on the SSF
    stream to the web RP.
    """

    def __init__(self, limit: int = _DENY_LIMIT, window_seconds: int = _WINDOW_SECONDS):
        self._limit = limit
        self._window = window_seconds
        self._hits: dict[str, list[float]] = {}
        self._lock = Lock()

    def record_deny(self, subject: str) -> int:
        now = time.time()
        with self._lock:
            stamps = [t for t in self._hits.get(subject, []) if now - t < self._window]
            stamps.append(now)
            self._hits[subject] = stamps
            return len(stamps)

    def should_revoke(self, subject: str) -> bool:
        with self._lock:
            stamps = self._hits.get(subject, [])
            now = time.time()
            return len([t for t in stamps if now - t < self._window]) >= self._limit

    def count(self, subject: str) -> int:
        now = time.time()
        with self._lock:
            return len([t for t in self._hits.get(subject, []) if now - t < self._window])

    def clear(self, subject: str) -> None:
        with self._lock:
            self._hits.pop(subject, None)


DENY_TRACKER = DenyTracker()
