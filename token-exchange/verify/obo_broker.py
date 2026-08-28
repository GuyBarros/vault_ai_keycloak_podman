import time
from dataclasses import dataclass

import jwt
import tenacity
import tenacity.stop
import tenacity.wait

from broker.cache import TokenCache
from exceptions.errors import OBORequestError
from app_logging.logger import get_logger
from verify.authorization import authorize_scope
from verify.verify_client import KeycloakTokenExchangeClient

logger = get_logger(__name__)


def _log_retry_attempt(retry_state: tenacity.RetryCallState) -> None:
    """Emit a warning log before each retry attempt."""
    exc = None
    if retry_state.outcome is not None and retry_state.outcome.failed:
        exc = retry_state.outcome.exception()
    next_sleep = None
    if retry_state.next_action is not None:
        next_sleep = retry_state.next_action.sleep

    logger.warning(
        "keycloak_obo_retry",
        attempt_number=retry_state.attempt_number,
        next_sleep_seconds=next_sleep,
        error=str(exc) if exc is not None else None,
    )


def claim_from_token(token: str, claim: str) -> str | None:
    """Return *claim* from *token* by decoding the JWT without verification."""
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return None
    value = payload.get(claim) if isinstance(payload, dict) else None
    return value if isinstance(value, str) else None


@dataclass
class OBOTokenResult:
    access_token: str
    cached: bool


class OBOBroker:
    """Broker that performs a Keycloak RFC 8693 token exchange.

    Public API:
        exchange_obo_token(subject_token, actor_token) -> OBOTokenResult
    """

    def __init__(
        self,
        verify_client: KeycloakTokenExchangeClient | None = None,
        cache: TokenCache | None = None,
    ) -> None:
        self._client = verify_client or KeycloakTokenExchangeClient()
        self._cache = cache or TokenCache()

    def exchange_obo_token(
        self, subject_token: str, actor_token: str, scope: str
    ) -> OBOTokenResult:
        """Return a Keycloak access token on behalf of *subject_token* (RFC 8693).

        Checks the cache first using a hashed key derived from both input tokens
        and the requested scope set. On a cache miss, calls Keycloak with
        automatic retry (3 attempts, exponential backoff) on transient failures.

        Args:
            subject_token: The caller's access token (JWT).
            actor_token:   The Vault Identity JWT acting on behalf of the subject.
            scope:         Space-separated OAuth scopes to request on the OBO token.

        Returns:
            :class:`OBOTokenResult` with the access token and cache flag.

        Raises:
            OBOAuthorizationError:  Caller's groups don't entitle the requested scope.
            OBOAuthenticationError: Entra rejected the request.
            OBORequestError:        Entra could not complete the exchange.
            CacheError:                 Unexpected cache failure.
        """
        start = time.monotonic()
        authorize_scope(subject_token, scope)
        preferred_username = claim_from_token(subject_token, "preferred_username")
        agent_id = claim_from_token(actor_token, "agent_id")

        normalized_scope = _normalize_scope(scope)
        # Compose actor_token + normalized scope into the second cache slot so the
        # same subject+actor pair with different scopes never share a cache entry.
        cache_slot = f"{actor_token}|{normalized_scope}"

        cached_token = self._cache.get(subject_token, cache_slot)
        if cached_token:
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.info(
                "keycloak_obo_token_exchange",
                message=f"OBO token exchange (cache hit) for scope={normalized_scope!r}",
                preferred_username=preferred_username,
                agent_id=agent_id,
                scope=normalized_scope,
                cache_hit=True,
                duration_ms=duration_ms,
            )
            return OBOTokenResult(access_token=cached_token, cached=True)

        response_data = self._fetch_with_retry(
            subject_token, actor_token, normalized_scope
        )
        access_token: str = response_data["access_token"]
        self._cache.set(subject_token, cache_slot, access_token)

        duration_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "keycloak_obo_token_exchange",
            message=f"OBO token exchange (issued by Keycloak) for scope={normalized_scope!r}",
            preferred_username=preferred_username,
            agent_id=agent_id,
            scope=normalized_scope,
            cache_hit=False,
            duration_ms=duration_ms,
        )
        return OBOTokenResult(access_token=access_token, cached=False)

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(OBORequestError),
        stop=tenacity.stop.stop_after_attempt(3),
        wait=tenacity.wait.wait_exponential(multiplier=0.5, min=0.5, max=4),
        before_sleep=_log_retry_attempt,
        reraise=True,
    )
    def _fetch_with_retry(
        self, subject_token: str, actor_token: str, scope: str
    ) -> dict:
        return self._client.exchange_obo_token(subject_token, actor_token, scope)


def _normalize_scope(scope: str) -> str:
    """Return *scope* with tokens deduped, sorted, and single-space-joined.

    Ensures cache key stability across callers that send the same scope set in
    different orders (e.g. "users.write users.read" == "users.read users.write").
    """
    parts = sorted({tok for tok in scope.split() if tok})
    return " ".join(parts)
