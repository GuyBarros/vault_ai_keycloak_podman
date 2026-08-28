import requests
import structlog
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from broker.broker import VaultIdentityBroker
from exceptions.errors import (
    CacheError,
    OBOAuthenticationError,
    OBOAuthorizationError,
    OBORequestError,
    VaultAuthenticationError,
    VaultTokenGenerationError,
)
from app_logging.logger import get_logger
from models.schemas import (
    OBOTokenRequest,
    OBOTokenResponse,
    TokenRequest,
    TokenResponse,
)
from verify.obo_broker import OBOBroker, claim_from_token

router = APIRouter()
logger = get_logger(__name__)

# Single shared broker instances (cache is inside each broker).
_broker = VaultIdentityBroker()
_obo_broker = OBOBroker()


@router.post("/v1/identity/token", response_model=TokenResponse)
async def exchange_token(request: Request, body: TokenRequest) -> TokenResponse:
    """Exchange a Vault token for a Vault-signed OIDC Identity JWT."""
    try:
        result = _broker.get_signed_identity_token(
            vault_token=body.vault_token,
            role_name=body.role_name,
        )
        return TokenResponse(
            identity_token=result.identity_token,
            expires_at=result.expires_at,
            cached=result.cached,
        )

    except VaultAuthenticationError as exc:
        logger.warning(
            "token_exchange_auth_failure", role_name=body.role_name, error=str(exc)
        )
        return JSONResponse(status_code=401, content={"detail": str(exc)})

    except (VaultTokenGenerationError, CacheError) as exc:
        logger.error(
            "token_exchange_internal_error", role_name=body.role_name, error=str(exc)
        )
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    except requests.exceptions.ConnectionError as exc:
        logger.error("vault_unavailable", role_name=body.role_name, error=str(exc))
        return JSONResponse(status_code=503, content={"detail": "Vault is unavailable"})

    except Exception as exc:
        logger.exception(
            "token_exchange_unexpected_error", role_name=body.role_name, error=str(exc)
        )
        return JSONResponse(
            status_code=500, content={"detail": "Internal server error"}
        )


@router.post("/v1/identity/obo-token", response_model=OBOTokenResponse)
async def exchange_obo_token(
    request: Request, body: OBOTokenRequest
) -> OBOTokenResponse:
    """Exchange subject_token + actor_token for an IdP OBO access token."""
    structlog.contextvars.bind_contextvars(
        preferred_username=claim_from_token(body.subject_token, "preferred_username"),
        agent_id=claim_from_token(body.actor_token, "agent_id"),
    )
    try:
        result = _obo_broker.exchange_obo_token(
            subject_token=body.subject_token,
            actor_token=body.actor_token,
            scope=body.scope,
        )
        return OBOTokenResponse(
            access_token=result.access_token,
            cached=result.cached,
        )

    except OBOAuthorizationError as exc:
        logger.warning("obo_token_exchange_authz_denied", error=str(exc))
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    except OBOAuthenticationError as exc:
        logger.warning("obo_token_exchange_auth_failure", error=str(exc))
        return JSONResponse(status_code=401, content={"detail": str(exc)})

    except (OBORequestError, CacheError) as exc:
        logger.error("obo_token_exchange_internal_error", error=str(exc))
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    except requests.exceptions.ConnectionError as exc:
        logger.error("identity_provider_unavailable", error=str(exc))
        return JSONResponse(
            status_code=503, content={"detail": "Identity provider is unavailable"}
        )

    except Exception as exc:
        logger.exception("obo_token_exchange_unexpected_error", error=str(exc))
        return JSONResponse(
            status_code=500, content={"detail": "Internal server error"}
        )


@router.get("/healthz")
async def health() -> dict:
    """Liveness probe."""
    return {"status": "ok"}
