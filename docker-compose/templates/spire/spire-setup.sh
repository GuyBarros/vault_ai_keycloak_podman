#!/bin/sh
set -e

SOCKET=/tmp/spire-server/private/api.sock
SPIRE_VERSION=1.11.1
SPIRE_CLI=/tmp/spire-server-cli

# Download the spire-server CLI if not already present.
if [ ! -x "$SPIRE_CLI" ]; then
  echo "spire-setup: downloading spire-server CLI v${SPIRE_VERSION}..."
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "unsupported arch: $ARCH"; exit 1 ;;
  esac
  wget -qO /tmp/spire.tar.gz \
    "https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-${ARCH}-musl.tar.gz"
  tar -xzf /tmp/spire.tar.gz -C /tmp \
    "spire-${SPIRE_VERSION}/bin/spire-server"
  mv "/tmp/spire-${SPIRE_VERSION}/bin/spire-server" "$SPIRE_CLI"
  chmod +x "$SPIRE_CLI"
  rm -f /tmp/spire.tar.gz
fi

# Wait for the SPIRE server admin socket to be ready.
i=0
while [ ! -S "$SOCKET" ] && [ $i -lt 30 ]; do
  echo "spire-setup: waiting for server socket at $SOCKET ..."
  sleep 2
  i=$((i + 1))
done

echo "spire-setup: server socket ready."

# Create a join token for the agent.
# Note: the -spiffeID here is the agent SPIFFE ID; it must NOT start with
# /spire/ (reserved namespace). Use /agent/ instead.
JOIN_TOKEN=$($SPIRE_CLI token generate \
  -spiffeID "spiffe://example.org/agent/user-mcp" \
  -socketPath "$SOCKET" \
  -ttl 600 \
  | awk '{print $2}')

echo "spire-setup: join token generated: $JOIN_TOKEN"

# Write the token to the dedicated join-token volume.
echo "$JOIN_TOKEN" > /tmp/spire-join-token/join-token

echo "spire-setup: registering user-mcp workload entry..."

# Register the user-mcp workload bound to unix UID 1000.
$SPIRE_CLI entry create \
  -spiffeID "spiffe://example.org/user-mcp" \
  -parentID "spiffe://example.org/agent/user-mcp" \
  -selector "unix:uid:1000" \
  -socketPath "$SOCKET" \
  -jwtSVIDTTL 300 \
  -x509SVIDTTL 3600

echo "spire-setup: registering ai-agent (vault-agent) workload entry..."

# Register the ai-agent workload bound to unix UID 0 (vault-agent runs as root).
$SPIRE_CLI entry create \
  -spiffeID "spiffe://example.org/ai-agent" \
  -parentID "spiffe://example.org/agent/user-mcp" \
  -selector "unix:uid:0" \
  -socketPath "$SOCKET" \
  -jwtSVIDTTL 300 \
  -x509SVIDTTL 3600

echo "spire-setup: done."
