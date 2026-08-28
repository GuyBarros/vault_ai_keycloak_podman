# Observability

Structured JSON logs to stdout via [pino](https://github.com/pinojs/pino), one record per line. The field shape mirrors the Streamlit `web-app/observability.py` output so a single Loki/ELK pipeline can ingest both apps.

## Configuration

| Env var | Default | Effect |
|---|---|---|
| `LOG_LEVEL` | `info` | pino level (`trace` … `fatal`) |
| `LOG_SERVICE_NAME` | `verify-vault-web-app` | `service` field |
| `LOG_ENVIRONMENT` | `development` | `environment` field |

`host` / `hostname` come from `os.hostname()`; `host_ip` is resolved at startup (best-effort `dns.lookup`, falls back to `127.0.0.1` on error).

## Record shape

```json
{
  "timestamp": "2026-04-24T11:31:02.123Z",
  "service": "verify-vault-web-app",
  "environment": "development",
  "host": "host-1",
  "hostname": "host-1",
  "host_ip": "10.0.1.42",
  "request_id": "8f7c…",
  "client_ip": "203.0.113.5",
  "request_path": "/api/agent/query",
  "process": 12345,
  "process_name": "node",
  "thread": 0,
  "thread_name": "main",
  "level": "INFO",
  "severity": "INFO",
  "logger": "verify_vault.api.agent.query",
  "module": "api.agent.query",
  "message": "[user=alice@ibm.com] Streaming agent response"
}
```

`thread` / `thread_name` are stubbed (Node has no threads in the same sense as Python); kept for schema parity with the Streamlit logs.

## Identity prefix

When the `preferred_username` field is bound on the request context, the pino mixin prepends `[user=<name>] ` to the `message` field. This matches the Streamlit `_apply_identity_message_prefix` behavior. Useful for ad-hoc grep across operator activity.

## Request context propagation

Implemented with Node's `AsyncLocalStorage`. Every API route handler is wrapped by `withRequestContext()`:

```ts
export const POST = withRequestContext(async (req) => {
  // request_id, client_ip, request_path are bound; preferred_username
  // is set from the session cookie (if any) before the inner handler runs.
});
```

`request_id` resolution order:
1. Incoming `X-Request-ID` header (preserved across hops)
2. `crypto.randomUUID()` (generated per request)

`client_ip` resolution order:
1. `x-forwarded-for` (first IP if list)
2. `x-real-ip`
3. `cf-connecting-ip`
4. `-` (unknown)

Outbound calls (token exchange, agent backend) use `buildOutboundHeaders()` to attach `X-Request-ID` so a single id traces the full hop chain.

## Sensitive value redaction

The pino formatter recursively redacts these keys (case-insensitive) from any logged object:

```
access_token, id_token, refresh_token, client_secret, code, code_verifier,
authorization, session_password, set-cookie, cookie
```

Replaced with `<redacted>`. Strings that contain a sensitive substring are **not** redacted — only field names. This keeps free-text messages readable while ensuring an accidental `log.info({access_token})` does not leak.

## Loggers

Convention: `getLogger('<area>.<module>')` returns a child of the root with `logger: 'verify_vault.<area>.<module>'`.

| Module | Logger name |
|---|---|
| `lib/auth/oauth.ts` | `verify_vault.auth.oauth` |
| `app/api/auth/callback/route.ts` | `verify_vault.api.auth.callback` |
| `app/api/agent/query/route.ts` | `verify_vault.api.agent.query` |
| `lib/agent/client.ts` | `verify_vault.services.agent_api` |

## Log examples

**Successful login:**
```json
{"timestamp":"…","level":"INFO","logger":"verify_vault.api.auth.callback","request_id":"a1b2…","request_path":"/api/auth/callback","message":"[user=alice@ibm.com] Authentication completed successfully"}
```

**Agent stream completed:**
```json
{"timestamp":"…","level":"INFO","logger":"verify_vault.api.agent.query","request_id":"a1b2…","request_path":"/api/agent/query","message":"[user=alice@ibm.com] Streaming agent response","historyLength":4}
```

**Premature stream end recovery:**
```json
{"timestamp":"…","level":"WARN","logger":"verify_vault.services.agent_api","request_id":"a1b2…","message":"Streaming agent API ended prematurely; preserving received content","streamedChunks":7,"err":"…"}
```

## Production tips

- Pin the `LOG_LEVEL` to `info` or higher in production; `debug` and `trace` emit per-request bookkeeping.
- The pino output is a single line of JSON; do not pipe through `pino-pretty` in production.
- If running behind a proxy that strips `x-forwarded-for`, set `client_ip` extraction header(s) accordingly in `lib/log/context.ts`.
- The `request_id` field is the first thing to grep when correlating across the browser, Next.js, IBM Verify, and the agent backend. Surface it in the UI's error toasts in a future iteration.
