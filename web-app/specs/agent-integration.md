# AI Agent Integration

The browser never talks to the agent backend directly. All calls are server-proxied through Next.js Route Handlers, which attach the access_token (read from the sealed session cookie) and propagate `X-Request-ID`.

## Endpoints (proxied)

| Browser hits | Proxies to | Contract |
|---|---|---|
| `POST /api/agent/query` | `POST ${AI_AGENT_API_URL}/v1/agent/query` | streaming `text/plain` (or single-shot `application/json`) |
| `GET /api/agent/tokens` | `GET ${AI_AGENT_API_URL}/v1/agent/tokens` | JSON `{actor_token, obo_token}` |

If `AI_AGENT_API_URL` is empty, both routes return `502 agent_unavailable` with a clear message.

## Request body — `/api/agent/query`

```json
{
  "message": "string, 1..1000 chars",
  "history": [
    { "role": "user" | "assistant", "content": "string" }
  ]
}
```

zod-validated; invalid bodies return `400 invalid_body` with the issue list.

## Outbound request to the agent backend

```
POST ${AI_AGENT_API_URL}/v1/agent/query
Authorization: Bearer ${access_token}
Content-Type: application/json
Accept: text/plain, application/json;q=0.9
X-Request-ID: ${propagated}

{
  "messages": [...history, {"role": "user", "content": message}],
  "stream": true
}
```

Timeout: 310s (matches the Python `(connect=10, read=300)` semantics).

## Streaming response handling

The route handler returns a `Response(ReadableStream)` to the browser. Inside the stream:

1. **`Content-Type: application/json`** — read the entire body, pull the first present field of `response | response_text | result | message`, run `normalizeMessageContent`, enqueue once, close.
2. **`text/plain` (or anything else)** — read chunks via `response.body.getReader()`. For each decoded chunk:
   - append to a `pending` buffer
   - call `splitStreamBuffer(pending)` to peel off any **trailing odd-count of backslashes** (an incomplete `\X` escape pair) — those bytes stay in `pending` for the next chunk
   - run the decodable prefix through `normalizeMessageContent` and enqueue
3. On completion, flush any remaining `pending`.
4. If the upstream stream closes prematurely **after** chunks have been received, log a warning, flush `pending`, close the stream cleanly (matches the Python `_is_premature_stream_end` behavior). If no chunks were received, the error propagates.

## Response normalization (`lib/agent/normalize.ts`)

Direct port of `web-app/services/response_normalization.py`:

| Input | Output |
|---|---|
| `"plain text"` | `"plain text"` |
| `'{"response_text": "hi"}'` | `"hi"` |
| `'{"response": "hi"}'` | `"hi"` |
| `'{"result": "hi"}'` | `"hi"` |
| `'{"message": "hi"}'` | `"hi"` |
| `'a\\nb'` (escaped multiline) | `"a\nb"` (real newline) |
| `'he said \\"x\\"'` | `'he said "x"'` |
| `'"wrapped\\nstring"'` | `"wrapped\nstring"` |

Heuristics for "looks escaped":
- contains `\n` and no real `\n` (multiline)
- contains `\"` and no real `"` (quoted)
- starts with `"` and contains escape markers (wrapped)

Otherwise content is returned unchanged.

## Token panel (`/api/agent/tokens`)

Returns `{actor_token: string, obo_token: string}`. The upstream payload is unwrapped recursively: it can be the direct shape, nested under `data | result | response | payload | body`, or a stringified-JSON wrapping any of the above. Missing tokens are coerced to `""`.

After each successful chat send, the React `TokenInspector` increments a refresh key and re-fetches `/api/agent/tokens`. JWT payloads are decoded **client-side** (no signature verification — these are display-only) via `decodeJwtPayload()` in `lib/jwt-decode.ts`.

The Subject token comes from `/api/auth/claims` (the verified id_token claims, stored in the session cookie at login time). It loads on inspector mount and does not refresh per send.

## Error contract (server → browser)

| Condition | Status | Body |
|---|---|---|
| Missing/expired session | 401 | `{error: 'unauthenticated'}` |
| Invalid request body | 400 | `{error: 'invalid_body', issues: [...]}` |
| `AI_AGENT_API_URL` not configured | 502 | `{error: 'agent_unavailable', detail: '…'}` |
| Upstream HTTP error | 502 | `{error: 'agent_unavailable', detail: '…'}` |
| Cross-origin POST | 403 | `Forbidden: cross-origin request` (middleware) |

## What the existing Streamlit app did differently

- Streamed with `requests.iter_content(decode_unicode=True)` and a 60s/30s/(10s,300s) timeout matrix — ported as `AbortSignal.timeout(310_000)` for the read-window-equivalent.
- Used the same JSON envelope unwrapping and the same `_split_stream_buffer` semantics; ports preserve byte-for-byte behavior on the test cases in `tests/unit/normalize.test.ts` and `stream-split.test.ts`.
- Markdown rendering: Streamlit had heavy heuristics (`_format_message_markdown`, emoji escaping, structured-text detection). New app uses `react-markdown` + `remark-gfm` (per user decision); produces clean output for the common cases (lists, code, tables, links).
