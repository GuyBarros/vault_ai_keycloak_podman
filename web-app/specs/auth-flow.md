# Authentication & Session Flow

## OAuth 2.0 Authorization Code + PKCE (S256)

```
User                Browser                    Next.js                          Keycloak
 │                     │                          │                                  │
 │  click "Login"      │                          │                                  │
 │────────────────────►│                          │                                  │
 │                     │  GET /api/auth/login     │                                  │
 │                     │─────────────────────────►│                                  │
 │                     │                          │  generate state + PKCE verifier  │
 │                     │                          │  set sealed cookies              │
 │                     │                          │  redirect to /authorize?...      │
 │                     │  302 + Set-Cookie        │                                  │
 │                     │◄─────────────────────────│                                  │
 │                     │  GET /authorize?...                                        │
 │                     │──────────────────────────────────────────────────────────►  │
 │  login form         │                                                            │
 │◄────────────────────│  password / MFA                                            │
 │ submit              │                                                            │
 │────────────────────►│                                                            │
 │                     │  302 redirect_uri?code=&state=                             │
 │                     │◄──────────────────────────────────────────────────────────  │
 │                     │  GET /api/auth/callback  │                                  │
 │                     │─────────────────────────►│                                  │
 │                     │                          │  validate state (timing-safe)    │
 │                     │                          │  POST /token                     │
 │                     │                          │     code, code_verifier,         │
 │                     │                          │     client_id, client_secret     │
 │                     │                          │─────────────────────────────────►│
 │                     │                          │  ◄──{access_token, id_token,…}── │
 │                     │                          │  GET /jwks (cached) ────────────►│
 │                     │                          │  ◄── JWKS ──────────────────────│
 │                     │                          │  jose.jwtVerify(id_token, …)     │
 │                     │                          │  set sealed verify_session       │
 │                     │  302 /landing            │                                  │
 │                     │◄─────────────────────────│                                  │
 │                     │  GET /landing                                               │
 │                     │─────────────────────────►│                                  │
 │  ◄── workspace ─────│                                                            │
```

## Endpoints called on Keycloak

| Endpoint | Method | Purpose |
|---|---|---|
| `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth` | GET (redirect) | start flow |
| `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token` | POST | exchange code for tokens |
| `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs` | GET | public keys for id_token verification |
| `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/logout` | GET (redirect) | RP-initiated end-session |

## Cookie contract

| Name | Sealed | HttpOnly | Secure (prod) | SameSite | Path | Max-Age | Contents |
|---|---|---|---|---|---|---|---|
| `verify_session` | yes (iron-session AES-GCM) | ✅ | ✅ | Lax | `/` | id_token exp, cap 8h | `{access_token, id_token, expires_at, user_info, preferred_username, id_claims}` |
| `verify_oauth_state` | yes | ✅ | ✅ | Lax | `/api/auth/callback` | 10 min | `{state}` |
| `verify_pkce_verifier` | yes | ✅ | ✅ | Lax | `/api/auth/callback` | 10 min | `{verifier}` |
| `verify_theme` | no | (set client-side) | n/a | Lax | `/` | 1 year | `white` or `g100` |

`SESSION_PASSWORD` (env var, ≥32 chars) is the symmetric key for sealing. Rotate by updating the env var; existing sessions are invalidated (users will re-login).

## State + PKCE

- `state` — `crypto.randomBytes(16).toString('base64url')` (~22 chars)
- `code_verifier` — `crypto.randomBytes(32).toString('base64url')` (43 chars, RFC 7636 §4.1)
- `code_challenge = base64url(sha256(verifier))`, sent as `code_challenge_method=S256`
- Cookies are stored with `Path=/api/auth/callback` so they're not visible to other routes and are cleared after one use.

## id_token verification

```ts
jose.jwtVerify(id_token, createRemoteJWKSet(JWKS_URL), {
  audience: KEYCLOAK_CLIENT_ID,
  algorithms: ['RS256'],
});
```

`exp` is verified by default. The decoded claims are stored in the session cookie so the inspector can show them without re-fetching.

## Logout (RP-initiated, OIDC end-session)

`GET /api/auth/logout` clears all cookies (`maxAge: 0` on each), then 302s to:

```
${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/logout
  ?post_logout_redirect_uri=${KEYCLOAK_LOGOUT_URI}
  &id_token_hint=${session.id_token}
```

Keycloak revokes the SSO session and redirects back to `KEYCLOAK_LOGOUT_URI`.

## Error paths

| Condition | Response |
|---|---|
| Missing `code` or `state` in callback | 400 `Missing code or state` |
| `state` mismatch / cookie missing | 400 `Invalid OAuth state`, cookies cleared |
| Token exchange HTTP error | 500 `Authentication failed`, cookies cleared, server log includes status |
| id_token verification fails | 500 `Authentication failed`, cookies cleared |
| `?error=...` from Keycloak | 302 to `/?error=<urlencoded>` |
| Session expired | middleware 302 to `/` (HTML routes) or 401 (API routes) |

## What the existing Streamlit app did differently

- No PKCE — only `state`. New app adds PKCE S256 (defense in depth).
- Cookies stored in `st.session_state` (memory) — new app uses HttpOnly sealed cookies.
- Callback at `/` — new app uses `/api/auth/callback`. **Update the Keycloak client config** and `KEYCLOAK_REDIRECT_URI` accordingly.
