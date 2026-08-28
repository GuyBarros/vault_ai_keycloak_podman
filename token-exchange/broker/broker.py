import time
from dataclasses import dataclass

import jwt
import tenacity
import tenacity.stop
import tenacity.wait

from broker.cache import TokenCache
from broker.vault_client import VaultClient
from exceptions.errors import VaultTokenGenerationError
from app_logging.logger import get_logger

logger = get_logger(__name__)


@dataclass
class IdentityTokenResult:
    identity_token: str
    expires_at: int
    cached: bool


def _extract_exp(token: str) -> int:
    """Decode JWT without verification and return the *exp* claim."""
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
        return int(claims["exp"])
    except Exception:
        # Fallback: treat token as expiring 1 hour from now.
        return int(time.time()) + 3600


class VaultIdentityBroker:
    """Broker that exchanges a Vault token for a Vault-signed OIDC Identity JWT.

    Public API:
        get_signed_identity_token(vault_token, role_name) -> IdentityTokenResult
    """

    def __init__(
        self,
        vault_client: VaultClient | None = None,
        cache: TokenCache | None = None,
    ) -> None:
        self._client = vault_client or VaultClient()
        self._cache = cache or TokenCache()

    def get_signed_identity_token(
        self, vault_token: str, role_name: str
    ) -> IdentityTokenResult:
        """Return a signed identity JWT for the given Vault token and role.

        Checks the cache first. On a miss, calls Vault with automatic retry
        (3 attempts, exponential backoff) on transient/5xx errors.

        Args:
            vault_token: A valid Vault service/batch token.
            role_name:   The Vault OIDC named role to use.

        Returns:
            :class:`IdentityTokenResult` with the JWT, expiry, and cache flag.

        Raises:
            VaultAuthenticationError:  Token is invalid or lacks permission.
            VaultTokenGenerationError: Vault could not generate the token.
            CacheError:                Unexpected cache failure.
        """
        start = time.monotonic()

        cached_token = self._cache.get(vault_token, role_name)
        if cached_token:
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.info(
                "vault_token_exchange",
                role_name=role_name,
                cache_hit=True,
                duration_ms=duration_ms,
            )
            return IdentityTokenResult(
                identity_token=cached_token,
                expires_at=_extract_exp(cached_token),
                cached=True,
            )

        token = self._fetch_with_retry(vault_token, role_name)
        self._cache.set(vault_token, role_name, token)

        duration_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "vault_token_exchange",
            role_name=role_name,
            cache_hit=False,
            duration_ms=duration_ms,
        )
        return IdentityTokenResult(
            identity_token=token,
            expires_at=_extract_exp(token),
            cached=False,
        )

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(VaultTokenGenerationError),
        stop=tenacity.stop.stop_after_attempt(3),
        wait=tenacity.wait.wait_exponential(multiplier=0.5, min=0.5, max=4),
        reraise=True,
    )
    def _fetch_with_retry(self, vault_token: str, role_name: str) -> str:
        return self._client.generate_signed_id_token(vault_token, role_name)
