#!/bin/sh
# Prove ACL policy ciba-list-users is the list-users CIBA switch per actor.
set -eu

KC_URL="${KC_URL:-http://localhost:8081}"
VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
CIBA_UI="${CIBA_UI:-http://localhost:8093}"
CLIENT_ID="${CLIENT_ID:-token-exchange}"
CLIENT_SECRET="${CLIENT_SECRET:-token-exchange-secret}"
CIBA_ID="${CIBA_ID:-ciba-client}"
CIBA_SECRET="${CIBA_SECRET:-ciba-client-secret}"

pass=0
fail=0

expect() {
  _title=$1
  _got=$2
  _want=$3
  if [ "${_got}" = "${_want}" ]; then
    echo "PASS  ${_title} (http ${_got})"
    pass=$((pass + 1))
  else
    echo "FAIL  ${_title} (got ${_got}, want ${_want})"
    fail=$((fail + 1))
  fi
}

kc_password() {
  _user=$1
  _pass=$2
  _scope=$3
  _body=$(curl -sS -X POST "${KC_URL}/realms/demo/protocol/openid-connect/token" \
    -d "client_id=${CLIENT_ID}" \
    -d "client_secret=${CLIENT_SECRET}" \
    -d "grant_type=password" \
    -d "username=${_user}" \
    -d "password=${_pass}" \
    -d "scope=${_scope}")
  printf '%s' "${_body}" | python3 -c '
import json, sys
d = json.load(sys.stdin)
if "access_token" not in d:
    raise SystemExit("token request failed: " + json.dumps(d)[:500])
print(d["access_token"])
'
}

vault_login_mcp() {
  _jwt=$1
  _role=$2
  docker exec -e V_JWT="${_jwt}" -e V_ROLE="${_role}" user-mcp \
    /app/.venv/bin/python -c '
import json, os, sys, urllib.error, urllib.request
payload = json.dumps({"role": os.environ["V_ROLE"], "jwt": os.environ["V_JWT"]}).encode()
req = urllib.request.Request(
    "http://vault:8200/v1/auth/jwt-keycloak/login",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        sys.stdout.write(str(resp.status))
except urllib.error.HTTPError as exc:
    sys.stdout.write(str(exc.code))
'
}

vault_ciba_switch() {
  _jwt=$1
  _user=$2
  docker exec -e V_JWT="${_jwt}" -e V_USER="${_user}" user-mcp \
    /app/.venv/bin/python -c '
import json, os, urllib.request
login = json.dumps({"role": "user-mcp-oidc-read", "jwt": os.environ["V_JWT"]}).encode()
req = urllib.request.Request(
    "http://vault:8200/v1/auth/jwt-keycloak/login",
    data=login,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=10) as resp:
    token = json.loads(resp.read())["auth"]["client_token"]
path = "ciba/list-users/" + os.environ["V_USER"]
cap_req = urllib.request.Request(
    "http://vault:8200/v1/sys/capabilities-self",
    data=json.dumps({"paths": [path]}).encode(),
    headers={"Content-Type": "application/json", "X-Vault-Token": token},
    method="POST",
)
with urllib.request.urlopen(cap_req, timeout=10) as resp:
    data = json.loads(resp.read()).get("data") or {}
caps = data.get(path) or data.get("capabilities") or []
print("read" if ("read" in caps and "deny" not in caps) else "deny")
'
}

echo "--- session OBO can assume oidc-read; ciba-list-users is per actor ---"
USER_READ=$(kc_password user user "openid users.read")
STATUS=$(vault_login_mcp "${USER_READ}" user-mcp-oidc-read)
expect "reader OBO allowed on oidc-read" "${STATUS}" "200"

ADMIN_READ=$(kc_password admin admin "openid users.read users.write")
STATUS=$(vault_login_mcp "${ADMIN_READ}" user-mcp-oidc-read)
expect "writer OBO allowed on oidc-read" "${STATUS}" "200"
SWITCH=$(vault_ciba_switch "${ADMIN_READ}" admin)
if [ "${SWITCH}" = "read" ]; then
  echo "PASS  ciba/list-users/admin is read (CIBA on for admin list-users)"
  pass=$((pass + 1))
else
  echo "FAIL  ciba/list-users/admin (got ${SWITCH}, want read)"
  fail=$((fail + 1))
fi

echo "--- write role still accepts session OBO ---"
ADMIN_WRITE=$(kc_password admin admin "openid users.write")
STATUS=$(vault_login_mcp "${ADMIN_WRITE}" user-mcp-oidc-write)
expect "writer OBO allowed on oidc-write" "${STATUS}" "200"

echo "--- CIBA approve then oidc-read ---"
CIBA_START=$(curl -sS -X POST "${KC_URL}/realms/demo/protocol/openid-connect/ext/ciba/auth" \
  -d "client_id=${CIBA_ID}" \
  -d "client_secret=${CIBA_SECRET}" \
  -d "login_hint=admin" \
  -d "scope=openid users.read" \
  -d "binding_message=prove-ciba-list-users")
AUTH_REQ_ID=$(printf '%s' "${CIBA_START}" | python3 -c '
import json, sys
d = json.load(sys.stdin)
if "auth_req_id" not in d:
    raise SystemExit("ciba start failed: " + json.dumps(d)[:500])
print(d["auth_req_id"])
')
sleep 1
APPROVE=$(curl -sS -o /tmp/ciba-approve.json -w '%{http_code}' -X POST "${CIBA_UI}/approve-latest")
expect "ciba-channel callback" "${APPROVE}" "200"

CIBA_JWT=""
i=0
while [ "$i" -lt 20 ]; do
  TOK=$(curl -sS -X POST "${KC_URL}/realms/demo/protocol/openid-connect/token" \
    -d "grant_type=urn:openid:params:grant-type:ciba" \
    -d "auth_req_id=${AUTH_REQ_ID}" \
    -d "client_id=${CIBA_ID}" \
    -d "client_secret=${CIBA_SECRET}")
  CIBA_JWT=$(printf '%s' "${TOK}" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d.get("access_token", ""))
' || true)
  if [ -n "${CIBA_JWT}" ]; then
    break
  fi
  i=$((i + 1))
  sleep 2
done
if [ -z "${CIBA_JWT}" ]; then
  echo "FAIL  CIBA token poll returned no access_token"
  fail=$((fail + 1))
else
  echo "PASS  CIBA token issued after approve"
  pass=$((pass + 1))
  STATUS=$(vault_login_mcp "${CIBA_JWT}" user-mcp-oidc-read)
  expect "CIBA JWT allowed on oidc-read" "${STATUS}" "200"
fi

echo ""
echo "PASS=${pass} FAIL=${fail}"
[ "${fail}" -eq 0 ]
