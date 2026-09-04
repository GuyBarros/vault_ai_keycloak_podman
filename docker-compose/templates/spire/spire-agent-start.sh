#!/bin/sh
set -e

SPIRE_VERSION=1.11.1
SPIRE_AGENT=/tmp/spire-agent-bin

# Download the spire-agent binary if not already present.
if [ ! -x "$SPIRE_AGENT" ]; then
  echo "spire-agent-start: downloading spire-agent binary v${SPIRE_VERSION}..."
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
  mv "/tmp/spire-${SPIRE_VERSION}/bin/spire-agent" "$SPIRE_AGENT"
  chmod +x "$SPIRE_AGENT"
  rm -f /tmp/spire.tar.gz
fi

# Wait for the join token written by spire-setup.
echo "spire-agent-start: waiting for join token..."
i=0
while [ ! -f /tmp/spire-join-token/join-token ] && [ $i -lt 60 ]; do
  sleep 1
  i=$((i + 1))
done

if [ ! -f /tmp/spire-join-token/join-token ]; then
  echo "spire-agent-start: timed out waiting for join token."
  exit 1
fi

JOIN_TOKEN=$(cat /tmp/spire-join-token/join-token)
echo "spire-agent-start: starting spire-agent with join token."

exec "$SPIRE_AGENT" run \
  -config /etc/spire/agent/agent.conf \
  -joinToken "$JOIN_TOKEN"
