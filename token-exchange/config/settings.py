from app_logging.logger import get_logger
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


logger = get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="IDENTITY_BROKER_",
        case_sensitive=False,
        env_file=".env",
        extra="ignore",
    )

    vault_addr: str = "https://127.0.0.1:8200"
    vault_tls_verify: bool = True
    # Path to a PEM CA bundle for Vault's self-signed or private CA certificate.
    # When set, TLS verification uses this bundle instead of the default certifi roots.
    vault_ca_bundle: str | None = None

    # Keycloak RFC 8693 token exchange settings.
    # URL of the Keycloak server (e.g. http://keycloak:8080).
    keycloak_url: str = ""
    # Keycloak realm that hosts the token-exchange client.
    keycloak_realm: str = "demo"
    # client_id of the confidential service client that performs the exchange.
    obo_client_id: str = ""
    obo_client_auth_method: str = "client_secret"
    obo_client_assertion_type: str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    obo_client_secret: str = ""
    # RFC 8693 ``audience`` parameter: the resource server the exchanged token is for.
    keycloak_token_exchange_audience: str = "user-mcp"
    # Keycloak group names that entitle each scope (``groups`` claim).
    admin_group: str = "writers"
    readonly_group: str = "readers"

    cache_ttl: int = 3600       # seconds; also the TTLCache eviction window
    cache_maxsize: int = 1024   # max number of cached tokens

    log_level: str = "INFO"

    @model_validator(mode="after")
    def validate_obo_client_auth(self) -> "Settings":
        values = self.model_dump()
        auth_method = values.get("obo_client_auth_method", "").strip().lower()
        if auth_method not in {"client_secret", "client_assertion"}:
            raise ValueError(
                "obo_client_auth_method must be one of: client_secret, client_assertion"
            )

        if auth_method == "client_secret" and not (self.obo_client_secret or "").strip():
            raise ValueError(
                "obo_client_secret is required when obo_client_auth_method=client_secret"
            )

        return self

    def log_configured_values(self) -> None:
        values = self.model_dump()
        if values.get("obo_client_secret"):
            values["obo_client_secret"] = "***"
        logger.info("settings_loaded", **values)


settings = Settings()
