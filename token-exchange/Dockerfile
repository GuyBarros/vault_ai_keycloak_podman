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
COPY api/ ./api/
COPY app_logging/ ./app_logging/
COPY broker/ ./broker/
COPY config/ ./config/
COPY exceptions/ ./exceptions/
COPY models/ ./models/
COPY verify/ ./verify/

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=9090 \
    OTEL_RESOURCE_ATTRIBUTES=service.name=token-exchange \
    OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector.virtual.consul:4318

EXPOSE 9090

# CMD ["uvicorn", "api.main:app"]
CMD ["uvicorn", "api.main:app"]
