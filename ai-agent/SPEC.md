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

### Supported Endpoint

- `POST /chat`

This endpoint accepts the conversation payload and returns a streaming plain-text response.


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

- The `actor_token` is available at a configurable filesystem path.
- Default path: `/vault/secrets/actor-token`

Recommended configuration parameter:

- `ACTOR_TOKEN_PATH=/vault/secrets/actor-token`

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

1. Receive `POST /chat` request with message history.
2. Inspect the latest user message.
3. Prepare LangChain messages and tools.
4. Read `actor_token` from the configured file path.
5. Check the in-memory OBO cache and reuse a valid token when available.
6. If no valid cached token exists, call the token-exchange service to obtain a new OBO token.
7. Log exchange and cache activity according to the structured logging requirements.
8. Execute the normal LangChain chat and tool flow.
9. Stream plain-text chunks to the caller using `StreamingResponse(generate(), media_type="text/plain")`.
