#!/bin/sh
# vault-agent-start.sh
# Fetches a SPIFFE JWT-SVID from the SPIRE Workload API and writes it to a
# file that Vault Agent's jwt auto_auth method can read.  Refreshes the token
# in the background before it expires (JWT-SVID TTL is 300 s; refresh every
# 240 s to leave headroom).
set -e

SPIRE_VERSION=1.11.1
SPIRE_AGENT_BIN=/tmp/spire-agent-bin
JWT_PATH=/tmp/spire-jwt/svid.jwt
SOCKET=/tmp/spire-agent/api.sock
AUDIENCE=TESTING
REFRESH_INTERVAL=240

# ---------------------------------------------------------------------------
# Download the spire-agent CLI if not already present (shared with the
# spire-agent container which uses the same image and volume layout).
# ---------------------------------------------------------------------------
if [ ! -x "$SPIRE_AGENT_BIN" ]; then
  echo "vault-agent-start: downloading spire-agent binary v${SPIRE_VERSION}..."
  ARCH=${SPIRE_ARCH:-$(uname -m)}
  case "$ARCH" in
    x86_64|amd64)  ARCH=x86_64 ;;
    aarch64|arm64|arm) ARCH=arm64 ;;
    *) echo "unsupported arch: $ARCH"; exit 1 ;;
  esac
  wget -qO /tmp/spire.tar.gz \
    "https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-${ARCH}-musl.tar.gz"
  tar -xzf /tmp/spire.tar.gz -C /tmp \
    "spire-${SPIRE_VERSION}/bin/spire-agent"
  mv "/tmp/spire-${SPIRE_VERSION}/bin/spire-agent" "$SPIRE_AGENT_BIN"
  chmod +x "$SPIRE_AGENT_BIN"
  rm -f /tmp/spire.tar.gz
fi

# ---------------------------------------------------------------------------
# Wait for the SPIRE Workload API socket to be available.
# ---------------------------------------------------------------------------
echo "vault-agent-start: waiting for SPIRE Workload API socket..."
i=0
while [ ! -S "$SOCKET" ] && [ $i -lt 60 ]; do
  sleep 2
  i=$((i + 1))
done
if [ ! -S "$SOCKET" ]; then
  echo "vault-agent-start: timed out waiting for SPIRE socket." >&2
  exit 1
fi
echo "vault-agent-start: SPIRE socket ready."

# ---------------------------------------------------------------------------
# Fetch the first JWT-SVID and write it to the file Vault Agent will read.
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$JWT_PATH")"

fetch_jwt() {
  "$SPIRE_AGENT_BIN" api fetch jwt \
    -audience "$AUDIENCE" \
    -socketPath "$SOCKET" \
    2>/dev/null \
    | awk '/^token\(/ { getline; print $1; exit }'
}

TOKEN=$(fetch_jwt)
if [ -z "$TOKEN" ]; then
  echo "vault-agent-start: failed to fetch initial JWT-SVID." >&2
  exit 1
fi
printf '%s' "$TOKEN" > "$JWT_PATH"
echo "vault-agent-start: initial JWT-SVID written to $JWT_PATH"

# ---------------------------------------------------------------------------
# Background refresh loop — rewrites the file before the JWT-SVID expires.
# ---------------------------------------------------------------------------
(
  while true; do
    sleep "$REFRESH_INTERVAL"
    NEW_TOKEN=$(fetch_jwt)
    if [ -n "$NEW_TOKEN" ]; then
      printf '%s' "$NEW_TOKEN" > "${JWT_PATH}.tmp"
      mv "${JWT_PATH}.tmp" "$JWT_PATH"
      echo "vault-agent-start: JWT-SVID refreshed."
    else
      echo "vault-agent-start: WARNING — JWT-SVID refresh failed, keeping existing token." >&2
    fi
  done
) &

# ---------------------------------------------------------------------------
# Start Vault Agent — it will read the JWT from $JWT_PATH.
# ---------------------------------------------------------------------------
echo "vault-agent-start: starting vault agent..."
exec vault agent -config=/vault/config/vault-agent.hcl
