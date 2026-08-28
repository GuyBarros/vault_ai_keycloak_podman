#!/bin/sh
elapsed=0
until [ -s /vault/secrets/litellm.env ]; do
  if [ "$elapsed" -ge 60 ]; then
    echo "timed out waiting for /vault/secrets/litellm.env" >&2
    exit 1
  fi
  echo "waiting for litellm.env... ($elapsed s)"
  sleep 1
  elapsed=$((elapsed + 1))
done
set -a
. /vault/secrets/litellm.env
set +a
exec litellm --config /app/config.yaml
