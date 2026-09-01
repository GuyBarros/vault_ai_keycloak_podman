# syntax=docker/dockerfile:1.7
FROM ghcr.io/astral-sh/uv:latest AS uv
FROM python:3.12-slim

COPY --from=uv /uv /uvx /bin/

WORKDIR /app
ENV PATH="/app/.venv/bin:$PATH"

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY agent_api.py agent_runtime.py config.py errors.py identity.py logging_utils.py mcp_client.py models.py pii_masking.py scoped_tool.py security.py tools.py ./

EXPOSE 8000


CMD ["uvicorn", "agent_api:app", "--host", "0.0.0.0", "--port", "8000"]

