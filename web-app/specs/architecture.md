# Architecture

## Goal

Recreate the Streamlit `web-app/` (Python, IBM Verify OAuth, AI agent chat) in Next.js + IBM Carbon, with the visual design from `specs/design/` and identical functional behavior. The new app reuses the same `.env` contract and runs on port `8080`.

## High-level shape

```
            ┌───────── Browser ─────────┐
            │  /  /landing  (HTML)      │
            │  /api/* (JSON, streams)   │
            └────────────┬──────────────┘
                         │ HttpOnly sealed cookies
                         ▼
            ┌──────── Next.js ──────────┐
            │  App Router (RSC + RH)    │
            │                           │
            │  middleware.ts            │  auth gating + same-origin guard
            │  app/                     │  pages + route handlers
            │  lib/auth/*               │  OAuth, JWT, session, PKCE
            │  lib/agent/*              │  streaming proxy + normalize
            │  lib/log/*                │  pino + AsyncLocalStorage
            └─────┬───────────────┬─────┘
                  │               │
        ┌─────────▼───┐    ┌──────▼─────────┐
        │ IBM Verify  │    │  AI Agent API  │
        │  /authorize │    │  /v1/agent/    │
        │  /token     │    │     query      │
        │  /jwks      │    │     tokens     │
        │  /logout    │    └────────────────┘
        └─────────────┘
```

## Directory map

```
src/
├── app/
│   ├── layout.tsx                  # <html data-carbon-theme>, fonts, ThemeProvider
│   ├── page.tsx                    # Login page (g100)
│   ├── globals.scss                # Carbon themes + style entrypoint
│   ├── landing/page.tsx            # auth-gated; Header + ChatWorkspace
│   ├── loading.tsx · error.tsx · not-found.tsx
│   └── api/
│       ├── auth/{login,callback,logout,claims,me}/route.ts
│       └── agent/{query,tokens}/route.ts
├── components/
│   ├── ibm-logo.tsx · icons.tsx
│   ├── header.tsx · theme-select.tsx · logout-button.tsx
│   ├── login-page.tsx · theme-provider.tsx
│   ├── chat/
│   │   ├── chat-workspace.tsx      # state owner
│   │   ├── hero-panel.tsx
│   │   ├── message-log.tsx · message-bubble.tsx · typing-indicator.tsx
│   │   ├── composer.tsx · stream-client.ts
│   └── inspector/
│       ├── token-inspector.tsx     # accordion x3
│       └── token-claims.tsx
├── lib/
│   ├── config.ts                   # zod env, fail-fast
│   ├── auth/{oauth,jwks,jwt,session,pkce,cookies}.ts
│   ├── agent/{client,normalize,stream}.ts
│   ├── log/{logger,context,outbound,with-request-context}.ts
│   ├── http/same-origin.ts
│   └── jwt-decode.ts               # client-only payload decode for inspector
├── middleware.ts
├── styles/{header,login,hero,chat,inspector,composer}.scss
└── types/{env.d.ts, agent.d.ts}
```

## Request flow — chat send

```
ChatWorkspace.handleSend()
  └─► fetch POST /api/agent/query   (cookie-authenticated, JSON body)
        └─► middleware.ts            (same-origin check, session cookie present)
              └─► app/api/agent/query/route.ts
                    ├─ getSession()             → reads sealed verify_session cookie
                    ├─ zod validates body       → {message, history}
                    └─ invokeStream()           → fetch AI_AGENT_API_URL/v1/agent/query
                          ├─ Authorization: Bearer access_token
                          ├─ X-Request-ID: <propagated>
                          └─ ReadableStream pipes back to browser as text/plain
        ◄─── streaming chunks ───
  StreamClient decodes chunks → setPending({text: acc})
  onDone → setMessages(...prev, {role:'agent', text: acc})
  trigger /api/agent/tokens refresh in TokenInspector
```

## Trust boundaries

| Boundary | What crosses | Protection |
|---|---|---|
| Browser ↔ Next.js | HTTP requests, sealed cookies | HttpOnly + Secure (prod) + SameSite=Lax cookies; same-origin check on POST |
| Next.js ↔ IBM Verify | OAuth flows + JWKS | TLS; client_secret in token request body; PKCE S256 |
| Next.js ↔ AI Agent API | Bearer access_token | TLS; token never reaches browser; X-Request-ID propagated |

## State stores

| State | Where | Lifetime |
|---|---|---|
| `verify_session` cookie | sealed (iron-session) | id_token `exp` (cap 8h) |
| `verify_oauth_state` | sealed cookie scoped `/api/auth/callback` | 10 min |
| `verify_pkce_verifier` | sealed cookie scoped `/api/auth/callback` | 10 min |
| `verify_theme` | plain cookie (HttpOnly false) | 1 year |
| Chat messages | client React state | session lifetime |

## Threat model (summary)

- **XSS exfil of tokens** — mitigated by HttpOnly cookies + restrictive CSP. Token inspector shows raw JWT only because it's already in the (server-readable) cookie; `/api/auth/claims` and `/api/agent/tokens` are auth-gated server endpoints.
- **CSRF on chat send** — `POST /api/agent/*` requires same-origin (`Origin` or `Referer` matches). SameSite=Lax cookie defends against cross-site form posts.
- **State / authorization-code injection** — `state` and PKCE `code_verifier` validated; constant-time compare; one-shot cookies cleared after use.
- **Open redirect** — all redirect URIs are constructed server-side from validated config; no user-supplied next-url params.
- **Log leakage** — pino serializer redacts `access_token`, `id_token`, `client_secret`, `code`, `code_verifier`, `authorization`, `cookie`, `set-cookie` recursively.
- **Replay of expired tokens** — `getSession()` rejects sessions whose `expires_at` has passed; middleware redirects to login.
- **Rate limiting** — TODO (commented in `/api/agent/query/route.ts`); add at edge before production.

## Coexistence with `web-app/`

The Streamlit app and this Next.js app share the IBM Verify config and (optionally) the AI agent backend. They both bind port 8080 by default; stop one before running the other locally. They do not share cookies (cookie names are scoped to this app).
