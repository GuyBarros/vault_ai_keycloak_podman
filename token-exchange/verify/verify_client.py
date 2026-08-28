import requests
import jwt
import time

from config.settings import settings
from exceptions.errors import (
    OBOAuthenticationError,
    OBORequestError,
)
from app_logging.logger import get_logger

logger = get_logger(__name__)

# RFC 8693 grant type (same for Keycloak and Entra)
_RFC8693_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
# RFC 8693 token type URNs
_TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
_TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"

_EXP_LEEWAY_SECONDS = 30


class KeycloakTokenExchangeClient:
    """HTTP client for Keycloak RFC 8693 token exchange.

    Performs a token exchange against the Keycloak token endpoint.
    The service client authenticates using ``client_secret`` (default) or a
    ``client_assertion`` JWT (when ``client_auth_method=client_assertion``).

    Keycloak token exchange must be enabled on the realm and the
    ``token-exchange`` client must be granted the ``token-exchange`` permission
    for the target ``audience`` resource.

    Configuration is read from :mod:`config.settings` at instantiation time.
    """

    def __init__(
        self,
        keycloak_url: str | None = None,
        realm: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        client_auth_method: str | None = None,
        client_assertion_type: str | None = None,
    ) -> None:
        base = (keycloak_url or settings.keycloak_url).rstrip("/")
        realm_name = realm or settings.keycloak_realm
        self._token_url = f"{base}/realms/{realm_name}/protocol/openid-connect/token"
        self._client_id = client_id or settings.obo_client_id
        self._client_secret = client_secret or settings.obo_client_secret
        self._client_auth_method = (
            client_auth_method or settings.obo_client_auth_method
        ).strip().lower()
        self._client_assertion_type = (
            client_assertion_type or settings.obo_client_assertion_type
        )

        if self._client_auth_method not in {"client_secret", "client_assertion"}:
            raise OBORequestError(
                "Invalid OBO client authentication method: "
                f"{self._client_auth_method!r}. Expected client_secret or client_assertion."
            )

    def exchange_obo_token(
        self, subject_token: str, actor_token: str, scope: str
    ) -> dict:
        """Exchange *subject_token* + *actor_token* for a Keycloak access token.

        Sends a RFC 8693 token exchange request to Keycloak:

        .. code-block:: http

            POST /realms/{realm}/protocol/openid-connect/token
            Content-Type: application/x-www-form-urlencoded

            grant_type=urn:ietf:params:oauth:grant-type:token-exchange
            &subject_token=<user-access-token>
            &subject_token_type=urn:ietf:params:oauth:token-type:access_token
            &actor_token=<vault-identity-jwt>
            &actor_token_type=urn:ietf:params:oauth:token-type:jwt
            &requested_token_type=urn:ietf:params:oauth:token-type:access_token
            &audience=user-mcp
            &scope=<space-separated scopes>
            &client_id=token-exchange
            &client_secret=... | &client_assertion=...

        Args:
            subject_token: The caller's access token (JWT) to act on behalf of.
            actor_token:   The Vault Identity JWT that identifies the acting service.
            scope:         Space-separated OAuth scopes to request on the exchanged token.

        Returns:
            Parsed JSON response dict from Keycloak (contains ``access_token``,
            ``token_type``, ``expires_in``, etc.).

        Raises:
            OBOAuthenticationError:  Keycloak returned 401.
            OBORequestError:         Any other HTTP or connection failure.
        """

        _ensure_token_not_expired("subject_token", subject_token)
        _ensure_token_not_expired("actor_token", actor_token)

        payload = self._build_rfc8693_payload(subject_token, actor_token, scope)

        logger.debug(
            "keycloak_token_exchange_payload",
            payload={
                k: (
                    v
                    if k not in {"subject_token", "actor_token", "client_secret", "client_assertion"}
                    else "<redacted>"
                )
                for k, v in payload.items()
            },
        )

        subject_token_diag = _token_diagnostics(subject_token)
        actor_token_diag = _token_diagnostics(actor_token)
        logger.debug(
            "keycloak_token_exchange_request_context",
            subject_token_diag=subject_token_diag,
            actor_token_diag=actor_token_diag,
        )

        try:
            response = requests.post(
                self._token_url,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10,
            )
        except requests.exceptions.RequestException as exc:
            raise OBORequestError(
                f"Network error contacting Keycloak: {exc}"
            ) from exc

        if response.status_code == 401:
            idp_error = _extract_idp_error(response)
            detail = idp_error.get("detail")
            if detail:
                raise OBOAuthenticationError(
                    f"Keycloak rejected the token exchange request: unauthorized ({detail})"
                )
            raise OBOAuthenticationError(
                "Keycloak rejected the token exchange request: unauthorized"
            )

        if not response.ok:
            idp_error = _extract_idp_error(response)
            logger.warning(
                "keycloak_token_exchange_http_error",
                status_code=response.status_code,
                response_body=response.text,
                idp_error=idp_error,
                subject_token_diag=subject_token_diag,
                actor_token_diag=actor_token_diag,
            )
            detail = idp_error.get("detail")
            if detail:
                raise OBORequestError(
                    f"Keycloak token exchange failed with HTTP {response.status_code}: {detail}"
                )
            raise OBORequestError(
                f"Keycloak token exchange failed with HTTP {response.status_code}"
            )

        try:
            return response.json()
        except Exception as exc:
            raise OBORequestError(
                "Keycloak returned a non-JSON response"
            ) from exc

    def _build_rfc8693_payload(
        self, subject_token: str, actor_token: str, scope: str
    ) -> dict:
        """Build the RFC 8693 form payload for Keycloak standard token exchange.

       https://www.keycloak.org/securing-apps/token-exchange#_token-exchange-delegation
       
        ``delegation:ai-agent`` is always included in the scope sent to Keycloak
        so the issued token carries the delegation claim regardless of which
        additional scopes the caller requested.
        """
        payload: dict[str, str] = {
            "grant_type": _RFC8693_GRANT_TYPE,
            "subject_token": subject_token,
            "subject_token_type": _TOKEN_TYPE_ACCESS_TOKEN,
            "requested_token_type": _TOKEN_TYPE_ACCESS_TOKEN,
            "audience": settings.keycloak_token_exchange_audience,
            "client_id": self._client_id,
        }

        scope_parts = {s for s in scope.split() if s}
        scope_parts.add("delegation:ai-agent")
        payload["scope"] = " ".join(sorted(scope_parts))

        if self._client_auth_method == "client_assertion":
            payload["client_assertion_type"] = self._client_assertion_type
            payload["client_assertion"] = actor_token
            return payload

        payload["client_secret"] = self._client_secret
        return payload


# ---------------------------------------------------------------------------
# Diagnostics helpers (unchanged from Entra version)
# ---------------------------------------------------------------------------

def _token_diagnostics(token: str) -> dict:
    """Return non-sensitive JWT metadata for troubleshooting verification failures."""
    diagnostics: dict = {"present": bool(token)}
    if not token:
        return diagnostics

    diagnostics["fingerprint"] = token[:10]
    diagnostics["jwt_segments"] = token.count(".") + 1
    try:
        header = jwt.get_unverified_header(token)
        diagnostics["header_alg"] = header.get("alg")
        diagnostics["header_kid"] = header.get("kid")
        diagnostics["header_typ"] = header.get("typ")
    except Exception:
        diagnostics["header_parse_error"] = True

    try:
        claims = jwt.decode(token, options={"verify_signature": False})
        diagnostics["iss"] = claims.get("iss")
        diagnostics["aud"] = claims.get("aud")
        diagnostics["sub"] = claims.get("sub")
        diagnostics["azp"] = claims.get("azp")
        diagnostics["exp"] = claims.get("exp")
        diagnostics["iat"] = claims.get("iat")
        diagnostics["nbf"] = claims.get("nbf")
        now_epoch = int(time.time())
        diagnostics["now"] = now_epoch
        exp = claims.get("exp")
        if isinstance(exp, (int, float)):
            diagnostics["expired"] = bool((int(exp) + _EXP_LEEWAY_SECONDS) < now_epoch)
    except Exception:
        diagnostics["claim_parse_error"] = True

    return diagnostics


def _extract_idp_error(response: requests.Response) -> dict:
    """Extract identity-provider error details from JSON/plain responses.

    Returns a dict with keys ``code`` and ``detail``.
    """
    detail: str | None = None
    code: str | None = None

    try:
        body = response.json()
    except Exception:
        body = None

    if isinstance(body, dict):
        parts: list[str] = []
        error = body.get("error")
        if isinstance(error, str) and error.strip():
            parts.append(error.strip())

        error_description = body.get("error_description")
        if isinstance(error_description, str) and error_description.strip():
            parts.append(error_description.strip())

        reason = body.get("reason")
        if isinstance(reason, str) and reason.strip():
            parts.append(reason.strip())

        message = body.get("message")
        if isinstance(message, str) and message.strip():
            parts.append(message.strip())

        if parts:
            detail = " ".join(parts)
    else:
        text = (response.text or "").strip()
        if text:
            detail = text

    if detail:
        code = None

    return {"code": code, "detail": detail}


def _ensure_token_not_expired(token_name: str, token: str) -> None:
    """Raise when *token* has an ``exp`` value older than now (+ leeway)."""
    diagnostics = _token_diagnostics(token)
    exp = diagnostics.get("exp")
    expired = diagnostics.get("expired")
    now = diagnostics.get("now")
    if isinstance(exp, (int, float)) and expired is True and isinstance(now, int):
        logger.warning(
            "keycloak_token_exchange_token_expired",
            token_name=token_name,
            exp=exp,
            now=now,
            leeway_seconds=_EXP_LEEWAY_SECONDS,
            iss=diagnostics.get("iss"),
            aud=diagnostics.get("aud"),
            sub=diagnostics.get("sub"),
            fingerprint=diagnostics.get("fingerprint"),
        )
        raise OBORequestError(
            f"{token_name} is expired before token exchange (exp={int(exp)}, now={now})"
        )
