# Copilot Instructions

We are building the app described in `SPEC.md`. Read that file for general architectural tasks, technical stack, and design decisions.

Keep you replies extremely concise and focus on conveying the key information. No unnecessary fluff, no long code snippets.

## Project Overview

Python-based **identity broker** that:
1. Exchanges a HashiCorp Vault token for a Vault-signed OIDC Identity JWT.
2. Performs an **IBM Verify on-behalf-of (OBO) token exchange** — takes a `subject_token` + `actor_token` (Vault Identity JWT) and returns an IBM Verify access token on behalf of the subject.

Exposes both flows as a FastAPI REST service with in-memory TTL caching.

## Architecture

```
Client → FastAPI Service (api/)
           ├── POST /v1/identity/token    → VaultIdentityBroker (broker/) → HashiCorp Vault
           └── POST /v1/identity/obo-token → OBOBroker (verify/)          → IBM Verify
```

Both library layers (`broker/`, `verify/`) are decoupled from the API layer and independently usable.

## Module Structure

```
.
├── api/
│   ├── main.py         # FastAPI app instantiation
│   └── routes.py       # POST /v1/identity/token, POST /v1/identity/obo-token, GET /healthz
├── broker/
│   ├── broker.py       # VaultIdentityBroker class (public: get_signed_identity_token)
│   ├── cache.py        # TTLCache wrapper with JWT expiry validation
│   └── vault_client.py # hvac.Client wrapper
├── verify/
│   ├── verify_client.py # IBMVerifyClient — HTTP POST to IBM Verify token endpoint
│   └── obo_broker.py    # OBOBroker class (public: exchange_obo_token)
├── models/
│   └── schemas.py      # Pydantic models: TokenRequest/Response, OBOTokenRequest/Response
├── app_logging/
│   └── logger.py       # structlog structured JSON logger setup
├── exceptions/
│   └── errors.py       # VaultBrokerError hierarchy + VerifyOBOError hierarchy
└── config/
    └── settings.py     # Pydantic settings (env vars)
```

## Key Conventions

### Cache Key
- Vault tokens: `sha256(vault_token + role_name)`
- OBO tokens: `sha256(subject_token + actor_token)`

Never store raw tokens as keys. Both flows reuse `TokenCache` from `broker/cache.py`.

### Cache Validation
Before returning a cached JWT, decode it and check `exp - 30s` (safety buffer). If expired or within buffer, refresh.

```python
if current_time < exp - SAFETY_BUFFER:  # SAFETY_BUFFER = 30
    return cached_token
```

### Vault Integration
Always set `client.token = vault_token` per-request. Token exchange uses:
```python
client.secrets.identity.generate_signed_id_token(name=role_name)
```

### IBM Verify OBO Integration
HTTP POST to `<VERIFY_BASE_URL>/oauth2/token` with form-encoded body:
```
client_id, grant_type=urn:ietf:params:oauth:grant-type:token-exchange,
requested_token_type=...:access_token, subject_token_type=...:access_token,
subject_token, actor_token_type=urn:demo:token-type:vault-identity-jwt, actor_token
```
Config via env: `IDENTITY_BROKER_VERIFY_BASE_URL`, `IDENTITY_BROKER_OBO_CLIENT_ID`.

### Error → HTTP Mapping
| Exception | HTTP |
|---|---|
| `VaultAuthenticationError` | 401 |
| `VaultTokenGenerationError` | 500 |
| `CacheError` | 500 |
| Vault unavailable | 503 |
| `VerifyAuthenticationError` | 401 |
| `VerifyTokenExchangeError` | 500 |
| IBM Verify unavailable | 503 |

### Retry Policy
Use `tenacity` for network/5xx failures on both Vault and IBM Verify: `max_attempts=3`, exponential backoff.

### Logging
Use `structlog` with structured JSON. **Never log `vault_token`, `subject_token`, `actor_token`, JWT values, or raw API responses.** Always include `cache_hit` and `duration_ms` in token exchange logs.

### Technology Stack
| Concern | Library |
|---|---|
| API | FastAPI + Uvicorn |
| Vault SDK | hvac |
| HTTP client (IBM Verify) | requests |
| Cache | cachetools.TTLCache |
| JWT | PyJWT |
| Retry | tenacity |
| Logging | structlog |
| Validation | pydantic |

### Security
- TLS verification must remain enabled on the Vault client
- Vault policy scope: `identity/oidc/token/<role_name>` only
- Cache is thread-safe; use `threading.Lock` when wrapping TTLCache

## API Contracts

`POST /v1/identity/token`

Request:
```json
{ "vault_token": "hvs.xxxx", "role_name": "payments-api" }
```
Response:
```json
{ "identity_token": "eyJ...", "expires_at": 1700000000, "cached": true }
```

`POST /v1/identity/obo-token`

Request:
```json
{ "subject_token": "eyJ...", "actor_token": "eyJ..." }
```
Response:
```json
{ "access_token": "eyJ...", "cached": false }
```
