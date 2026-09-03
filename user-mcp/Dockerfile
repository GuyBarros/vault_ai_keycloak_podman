# ── builder ──────────────────────────────────────────────────────────────────
# syntax=docker/dockerfile:1
# Build for multiple architectures: linux/amd64, linux/arm64
# docker buildx build --platform linux/amd64,linux/arm64 -t <image>:<tag> --push .
FROM python:3.12-slim AS builder

ENV UV_LINK_MODE=copy

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency manifests first for layer caching
COPY pyproject.toml uv.lock ./

# Install production dependencies only; application source is copied separately.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# ── runtime ───────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

WORKDIR /app

# Copy the dependency-only virtualenv and the application source tree.
COPY --from=builder /app/.venv /app/.venv
COPY auth/    ./auth/
COPY storage/ ./storage/
COPY tools/   ./tools/
COPY server.py mcp_app.py config.py errors.py logging_utils.py models.py vault_client.py spiffe_client.py vault_transform.py ./
# COPY users_repository.json ./

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8090

# Run as uid 1000, matching the "unix:uid:1000" selector on this workload's
# SPIRE registration entry (docker-compose/templates/spire/spire-setup.sh) —
# as root, SPIRE's Workload API would attest this process against the
# "unix:uid:0" selector instead and hand back the ai-agent/vault-agent SPIFFE
# identity rather than user-mcp's own.
RUN useradd --uid 1000 --no-create-home --shell /usr/sbin/nologin user-mcp \
    && chown -R user-mcp:user-mcp /app
USER 1000

EXPOSE 8090

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8090"]
