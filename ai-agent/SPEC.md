# PRD: AI Agent Runtime Security Demo Agent

## Overview

Build a FastAPI-based AI agent that accepts chat messages, applies lightweight prompt-administration controls, can invoke local tools when needed, and streams plain-text responses back to the caller.

The implementation must use **LangChain** as the agent orchestration framework.

## Goals

- Provide a single streaming chat API for end-user interaction.
- Support normal LLM chat with streamed text chunks.
- Read the `actor_token` from a configurable filesystem path populated by Vault Agent Injector.
- Perform OAuth 2.0 on-behalf-of token exchange using the token-exchange service.
- Accept the user access token from the `Authorization` bearer token on the API request.

## Framework and Runtime

- **Web framework:** FastAPI
- **Agent framework:** LangChain
- **Model integration:** LangChain chat model interface with streaming enabled
- **Response format:** `text/plain` via `StreamingResponse`

LangChain is responsible for:

- Message construction
- Tool binding and invocation
- Streaming model output
- Producing string chunks for the client response stream

## API Surface

### Supported Endpoints

- `POST /v1/agent/query` — streaming chat + tools
- `GET /v1/agent/tokens` — last actor / OBO / child OBO for the inspector

The query endpoint accepts the conversation payload and returns a streaming plain-text response.


## Request Model

The chat API accepts a list of messages. Each message includes:

- `role`
- `content`

Expected roles:

- `system`
- `user`
- `assistant`

## Normal Chat Flow

For standard chat requests, the API must return a streaming response driven by an internal generator:

```python
StreamingResponse(generate(), media_type="text/plain")
```

Where:

- `generate()` yields `str` chunks
- The chunks are produced from `llm.stream(...)`
- The client receives incremental plain-text output as it is generated

## Identity and OBO Token Flow

The agent performs an **OBO token exchange** for downstream identity-aware operations.

The OBO token exchange is performed using the **token-exchange service**. The user access token is supplied through the `Authorization` bearer token on the incoming API request, and the `actor_token` is read from the configured filesystem path.

### Actor Token Source

- Parent `actor_token` is at a configurable filesystem path populated by **vault-agent** (SPIFFE uid 0).
- Default path: `/vault/secrets/actor-token`
- Child actor JWT (sandbox): `/vault/child-secrets/child-actor-token` (`CHILD_ACTOR_TOKEN_PATH`), minted by **vault-agent-child** (uid 1001). The parent process cannot fetch that SVID.

Recommended configuration:

- `ACTOR_TOKEN_PATH=/vault/secrets/actor-token`
- `CHILD_ACTOR_TOKEN_PATH=/vault/child-secrets/child-actor-token`

`GET /v1/agent/tokens` returns `{actor_token, obo_token, child_obo_token}`. `child_obo_token` is set after `delegate_research` mints a read-only OBO (`act.sub` = `spiffe://example.org/ai-agent-child`, nested `act.act` = parent SPIFFE). The LLM still runs in the parent process; only the workload identity is sandboxed.

### CIBA and writes

CIBA is enforced in **user-mcp**, not in the agent. Reads (`users.read`) stay silent OBO. Writes (`users.write`) require Keycloak CIBA (`ciba/write/<user>` ACL = read). Three tool denies in five minutes (`deny_tracker.py`) call Keycloak Admin logout and raise `session_revoked`.

### Vault Behavior

There is no requirement for the application to retrieve a Vault token.

Vault authentication and secret materialization are handled by **vault-agent injector**, so the application only needs to read the actor token from the configured file path.

### OBO Exchange Requirements

- Read the actor token from the configured file path.
- Perform the OBO token exchange internally by calling the token-exchange service.
- Log the resulting OBO token as part of the runtime flow for observability and debugging.

Reference curl command for the token-exchange operation:

```bash
curl -X POST http://localhost:8080/v1/identity/obo-token \
  -H "Content-Type: application/json" \
  -d '{
    "subject_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "actor_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

## OBO Token Cache Requirements

- In-memory cache only
- Cache OBO token until expiry
- Use method inputs as cache key

### Cache Key

```python
cache_key = hash(subject_token + role_name)
```

### Cache Entry

```python
{
  obo_token,
  expiry_time
}
```

### Validation Logic

```python
if token exists AND expiry_time > now:
    return cached token
else:
    fetch new token
```

## Error Handling

Errors returned in structured format.

Example:

```text
500 Internal Server Error
```

```json
{
  "error": "identity_broker_unreachable",
  "message": "Failed to obtain OBO token"
}
```

### Error Categories

| Error | Description |
| --------------------- | ----------------------- |
| invalid_request | missing parameters |
| token_exchange_failed | identity broker failure |
| cache_error | cache corruption |
| agent_error | agent execution failure |
| agent_suspended | KV `agent-lifecycle/<id> enabled=false` |
| session_revoked | DenyTracker: 3 denies in 5 min; IdP session ended |

## Logging Requirements

Log format:

```text
JSON structured logs
```

Standard fields:

- timestamp
- level
- logger
- hostname
- host_ip
- module
- function or method name
- line number
- request_id
- http_method
- path
- client_ip

Log events:

| Event | Description |
| -------------------- | ------------------- |
| request_received | API invocation |
| token_cache_hit | cached token used |
| token_cache_miss | new token requested |
| identity_broker_call | external request |
| agent_execution | agent processing |
| response_sent | response completed |

Sensitive fields excluded:

- user token
- obo token
- vault token

The runtime must also log that the actor token file path was used, that the OBO exchange was attempted or completed, and that the resulting OBO token was produced for the runtime flow without logging the token value itself.

## High-Level Processing Flow

1. Receive `POST /v1/agent/query` request with message history.
2. Inspect the latest user message. Reject if OPA policy_denied or agent_suspended.
3. Prepare LangChain messages and tools (including `delegate_research`).
4. Read parent `actor_token` from `ACTOR_TOKEN_PATH`.
5. Check the in-memory OBO cache (key includes subject + actor + scope + RAR) and reuse a valid token when available.
6. If no valid cached token exists, call the token-exchange service (`delegation_act` = SPIFFE, `authorization_details` = `vault:path_access`).
7. On write tools, user-mcp runs CIBA; the agent waits on the MCP call.
8. On child delegate, read `CHILD_ACTOR_TOKEN_PATH` and mint a nested OBO (`users.read` only).
9. Three denies in five minutes: Keycloak Admin logout + `session_revoked`.
10. Stream plain-text chunks to the caller using `StreamingResponse(generate(), media_type="text/plain")`.
