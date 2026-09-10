#!/bin/sh
# Wait for Vault Agent to render litellm.env.  On a cold start Vault Agent must
# first: download the SPIRE binary, wait for the SPIRE socket, fetch a JWT-SVID,
# authenticate to Vault, then render the template.  300 s is sufficient headroom.
elapsed=0
until [ -s /vault/secrets/litellm.env ]; do
  if [ "$elapsed" -ge 300 ]; then
    echo "timed out waiting for /vault/secrets/litellm.env" >&2
    exit 1
  fi
  echo "waiting for litellm.env... ($elapsed s)"
  sleep 2
  elapsed=$((elapsed + 2))
done
set -a
. /vault/secrets/litellm.env
set +a
exec litellm --config /app/config.yaml
