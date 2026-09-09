#!/bin/sh
# Live checklist for the Vault + CIBA demo.
# Usage (from docker-compose/):
#   ./demo-status.sh          # one shot
#   ./demo-status.sh --watch  # refresh every 2s  (Ctrl-C to stop)
set -eu

INTERVAL="${DEMO_STATUS_INTERVAL:-2}"
WATCH=0
case "${1:-}" in
  -w|--watch) WATCH=1 ;;
  -h|--help)
    echo "Usage: $0 [--watch]"
    exit 0
    ;;
esac

unset DOCKER_HOST || true
if ! docker info >/dev/null 2>&1; then
  export DOCKER_CONTEXT=colima
fi

ok()   { printf '  \033[32mOK \033[0m %s\n' "$1"; }
bad()  { printf '  \033[31mDOWN\033[0m %s\n' "$1"; }
warn() { printf '  \033[33mWAIT\033[0m %s\n' "$1"; }

http_code() {
  curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 1 --max-time 2 "$1" 2>/dev/null || printf '000'
}

http_ok() {
  _code=$(http_code "$1")
  case "$_code" in
    2*|3*|404) ok "$2  ($_code  $1)" ;;
    *)         bad "$2  ($_code  $1)" ;;
  esac
}

ctr_status() {
  docker inspect -f '{{.State.Status}}{{if .State.Health}}/{{.State.Health.Status}}{{end}}' "$1" 2>/dev/null || printf 'missing'
}

ctr_line() {
  _st=$(ctr_status "$1")
  case "$_st" in
    running|running/healthy|running/) ok "$1  ($_st)" ;;
    running/starting) warn "$1  ($_st)" ;;
    missing) bad "$1  (not created)" ;;
    *) bad "$1  ($_st)" ;;
  esac
}

ciba_cap() {
  _user=$1
  _pol=$(docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root vault \
    vault policy read ciba-list-users 2>/dev/null || true)
  _block=$(printf '%s\n' "$_pol" | awk -v u="$_user" '
    $0 ~ "ciba/list-users/" u {p=1}
    p && /capabilities/ {print; exit}
  ')
  case "$_block" in
    *read*) ok "CIBA list-users/$_user  (read → phone Approve)" ;;
    *deny*) warn "CIBA list-users/$_user  (deny → silent OBO)" ;;
    *)      bad "CIBA list-users/$_user  (policy missing)" ;;
  esac
}

once() {
  clear 2>/dev/null || true
  printf '\033[1mDemo status\033[0m  %s\n' "$(date '+%H:%M:%S')"
  echo "  chat http://localhost:8080   audit http://localhost:8092   ciba http://localhost:8093"
  echo "  vault http://localhost:8200  keycloak http://localhost:8081"
  echo

  echo "Engine"
  if docker info >/dev/null 2>&1; then
    _ctx=$(docker context show 2>/dev/null || echo '?')
    ok "docker  (context $_ctx)"
  else
    bad "docker daemon  (start Colima: colima start)"
    echo
    echo "Ctrl-C to stop"
    return
  fi

  echo
  echo "Containers"
  for c in \
    vault keycloak postgres spire-server spire-agent vault-agent \
    user-mcp litellm ai-agent web token-exchange ciba-channel audit-trail opa
  do
    ctr_line "$c"
  done

  echo
  echo "HTTP"
  http_ok "http://localhost:8080/" "web chat"
  http_ok "http://localhost:8081/realms/demo" "keycloak"
  http_ok "http://localhost:8200/v1/sys/health" "vault"
  http_ok "http://localhost:8093/pending" "ciba channel"
  http_ok "http://localhost:8092/" "audit trail"
  http_ok "http://localhost:4000/health/liveliness" "litellm"

  echo
  echo "Authz"
  if docker exec spire-agent test -S /tmp/spire-agent/api.sock 2>/dev/null; then
    ok "SPIRE workload socket"
  else
    bad "SPIRE workload socket"
  fi
  if docker exec vault-agent grep -q '^ANTHROPIC_API_KEY=sk-ant-' /vault/secrets/litellm.env 2>/dev/null; then
    ok "LiteLLM Anthropic key rendered"
  else
    bad "LiteLLM Anthropic key  (vault-agent / litellm.env)"
  fi
  if docker exec user-mcp grep -q 'ciba_required_by_policy' /app/storage/postgres_repo.py 2>/dev/null; then
    ok "user-mcp image has CIBA ACL probe"
  else
    bad "user-mcp image missing CIBA ACL probe  (rebuild user-mcp)"
  fi
  ciba_cap admin
  ciba_cap user

  echo
  echo "Phone"
  if ! command -v adb >/dev/null 2>&1; then
    bad "adb not on PATH"
  elif ! adb devices 2>/dev/null | grep -q $'emulator-.*device$'; then
    bad "Android emulator  (AVD CommanderPhone_API35)"
  else
    ok "emulator  ($(adb devices | awk '/emulator-.*device/{print $1}'))"
    if adb reverse --list 2>/dev/null | grep -q 'tcp:8093'; then
      ok "adb reverse tcp:8093"
    else
      bad "adb reverse tcp:8093  (run: adb reverse tcp:8093 tcp:8093)"
    fi
    if adb shell pidof org.demo.ciba >/dev/null 2>&1; then
      ok "CIBA Approve app running"
    else
      warn "CIBA Approve not in foreground  (adb shell am start -n org.demo.ciba/.MainActivity)"
    fi
  fi

  echo
  if [ "$WATCH" -eq 1 ]; then
    echo "Refresh every ${INTERVAL}s  ·  Ctrl-C to stop"
  fi
}

if [ "$WATCH" -eq 1 ]; then
  trap 'printf "\n"; exit 0' INT TERM
  while true; do
    once
    sleep "$INTERVAL"
  done
else
  once
fi
