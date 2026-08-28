import hvac
import hvac.exceptions

from config.settings import settings
from exceptions.errors import VaultAuthenticationError, VaultTokenGenerationError
from app_logging.logger import get_logger

logger = get_logger(__name__)


class VaultClient:
    """Thin wrapper around hvac.Client.

    A new client instance is created per call so each request uses its own
    Vault token without any shared state.
    """

    def __init__(
        self,
        vault_addr: str | None = None,
        tls_verify: bool | None = None,
        ca_bundle: str | None = None,
    ) -> None:
        self._vault_addr = vault_addr or settings.vault_addr

        # Resolve the `verify` value passed to hvac.Client:
        #   - a CA bundle path (str) keeps TLS on while trusting a private/self-signed CA
        #   - True/False falls back to the standard bool behaviour
        resolved_ca_bundle = ca_bundle if ca_bundle is not None else settings.vault_ca_bundle
        if resolved_ca_bundle:
            self._tls_verify: bool | str = resolved_ca_bundle
        else:
            self._tls_verify = tls_verify if tls_verify is not None else settings.vault_tls_verify

    def generate_signed_id_token(self, vault_token: str, role_name: str) -> str:
        """Exchange *vault_token* for a Vault-signed OIDC identity JWT.

        Args:
            vault_token: A valid Vault service/batch token.
            role_name:   The Vault OIDC named role to use.

        Returns:
            The raw signed JWT string.

        Raises:
            VaultAuthenticationError:  Token is invalid or forbidden.
            VaultTokenGenerationError: Vault returned an unexpected error.
        """
        client = hvac.Client(url=self._vault_addr, verify=self._tls_verify)
        client.token = vault_token

        try:
            response = client.secrets.identity.generate_signed_id_token(name=role_name)
            token: str = response["data"]["token"]
            logger.debug("vault_token_generated", role_name=role_name)
            return token

        except hvac.exceptions.Forbidden as exc:
            logger.warning("vault_auth_failure", role_name=role_name, error=str(exc))
            raise VaultAuthenticationError(
                f"Vault token lacks permission for role '{role_name}'"
            ) from exc

        except hvac.exceptions.InvalidRequest as exc:
            logger.warning("vault_invalid_request", role_name=role_name, error=str(exc))
            raise VaultAuthenticationError(str(exc)) from exc

        except hvac.exceptions.VaultError as exc:
            logger.error("vault_token_generation_error", role_name=role_name, error=str(exc))
            raise VaultTokenGenerationError(
                f"Vault failed to generate token for role '{role_name}'"
            ) from exc
