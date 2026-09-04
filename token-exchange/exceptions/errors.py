class VaultBrokerError(Exception):
    """Base exception for all Vault identity broker errors."""


class VaultAuthenticationError(VaultBrokerError):
    """Raised when the supplied Vault token is invalid or lacks permission."""


class VaultTokenGenerationError(VaultBrokerError):
    """Raised when Vault fails to generate a signed identity token."""


class CacheError(VaultBrokerError):
    """Raised on unexpected cache read/write failures."""


class OBOExchangeError(Exception):
    """Base exception for OBO token exchange errors."""


class OBOAuthenticationError(OBOExchangeError):
    """Raised when the identity provider rejects the OBO request due to invalid credentials."""


class OBORequestError(OBOExchangeError):
    """Raised when the identity provider fails to complete the OBO token exchange."""


class OBOAuthorizationError(OBOExchangeError):
    """Raised when Keycloak's PDP (Authorization Services) doesn't grant the requested scope."""
