#!/bin/sh
# Unprivileged child workload (unix:uid:1001). Fetches only the child JWT-SVID
# and mints the child actor JWT. The parent vault-agent (uid 0) cannot obtain
# this SVID — same isolation idea as OpenShell's unprivileged sandbox user.
set -e

SPIRE_VERSION=1.11.1
SPIRE_AGENT_BIN=/tmp/spire-agent-bin
SOCKET=/tmp/spire-agent/api.sock
AUDIENCE=TESTING
REFRESH_INTERVAL=240
CHILD_SPIFFE="spiffe://example.org/ai-agent-child"
CHILD_ACTOR_PATH=/vault/child-secrets/child-actor-token

if [ ! -x "$SPIRE_AGENT_BIN" ]; then
  echo "vault-agent-child: downloading spire-agent binary v${SPIRE_VERSION}..."
  ARCH=${SPIRE_ARCH:-$(uname -m)}
  case "$ARCH" in
    x86_64|amd64)  ARCH=amd64 ;;
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

echo "vault-agent-child: waiting for SPIRE Workload API socket..."
i=0
while [ ! -S "$SOCKET" ] && [ $i -lt 60 ]; do
  sleep 2
  i=$((i + 1))
done
if [ ! -S "$SOCKET" ]; then
  echo "vault-agent-child: timed out waiting for SPIRE socket." >&2
  exit 1
fi
echo "vault-agent-child: SPIRE socket ready (uid=$(id -u))."

mkdir -p "$(dirname "$CHILD_ACTOR_PATH")"

fetch_jwt() {
  "$SPIRE_AGENT_BIN" api fetch jwt \
    -audience "$AUDIENCE" \
    -socketPath "$SOCKET" \
    -spiffeID "$CHILD_SPIFFE" \
    2>/dev/null \
    | awk '/^token\(/ { getline; print $1; exit }'
}

mint_child_actor() {
  child_svid=$(fetch_jwt)
  if [ -z "$child_svid" ]; then
    echo "vault-agent-child: child JWT-SVID not available yet." >&2
    return 1
  fi
  child_vault=$(VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}" vault write -field=token \
    auth/jwt-spiffe/login role=ai-agent-child-spiffe jwt="$child_svid" 2>/dev/null || true)
  if [ -z "$child_vault" ]; then
    echo "vault-agent-child: jwt-spiffe login failed." >&2
    return 1
  fi
  child_oidc=$(VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}" VAULT_TOKEN="$child_vault" \
    vault read -field=token identity/oidc/token/child-role 2>/dev/null || true)
  if [ -z "$child_oidc" ]; then
    echo "vault-agent-child: child OIDC mint failed." >&2
    return 1
  fi
  printf '%s' "$child_oidc" > "${CHILD_ACTOR_PATH}.tmp"
  mv "${CHILD_ACTOR_PATH}.tmp" "$CHILD_ACTOR_PATH"
  echo "vault-agent-child: actor JWT written to $CHILD_ACTOR_PATH"
}

i=0
while ! mint_child_actor; do
  i=$((i + 1))
  if [ "$i" -ge 30 ]; then
    echo "vault-agent-child: failed to mint child actor JWT." >&2
    exit 1
  fi
  sleep 2
done

while true; do
  sleep "$REFRESH_INTERVAL"
  mint_child_actor || echo "vault-agent-child: WARNING — refresh failed, keeping existing token." >&2
done
