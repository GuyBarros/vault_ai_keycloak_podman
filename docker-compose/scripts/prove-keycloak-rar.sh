#!/usr/bin/env bash
# Prove that a Keycloak-issued access token is accepted by Vault 2.1 OAuth RS
# and that RAR (authorization_details / vault:path_access) is enforced.
set -euo pipefail

KC_URL="${KC_URL:-http://localhost:8081}"
VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
REALM="${REALM:-demo}"
CLIENT_ID="${CLIENT_ID:-rar-cli}"
CLIENT_SECRET="${CLIENT_SECRET:-rar-cli-secret}"
READ_PATH="database/creds/user-mcp-read-role"
WRITE_PATH="database/creds/user-mcp-write-role"

need() { command -v "$1" >/dev/null || { echo "need $1" >&2; exit 1; }; }
need curl
need python3

b64url_decode() {
  python3 -c 'import sys,base64; s=sys.stdin.read().strip()+"==="; print(base64.urlsafe_b64decode(s.encode()).decode())'
}

decode_jwt_part() {
  local jwt="$1" idx="$2"
  python3 - "$jwt" "$idx" <<'PY'
import json, sys, base64
jwt, idx = sys.argv[1], int(sys.argv[2])
part = jwt.split(".")[idx]
pad = "=" * (-len(part) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(part + pad)), indent=2))
PY
}

mint() {
  local user="$1" pass="$2" scope="$3"
  shift 3
  curl -sS -X POST \
    "${KC_URL}/realms/${REALM}/protocol/openid-connect/token" \
    -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -d "grant_type=password" \
    -d "username=${user}" \
    -d "password=${pass}" \
    -d "scope=${scope}" \
    "$@"
}

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

vault_get() {
  local token="$1" path="$2"
  curl -sS -o /tmp/vault-rar-body.json -w "%{http_code}" \
    -H "X-Vault-Token: ${token}" \
    "${VAULT_ADDR}/v1/${path}"
}

echo "== mint user token (users.read) =="
USER_RESP=$(mint user user "openid users.read")
USER_JWT=$(printf '%s' "${USER_RESP}" | json_field access_token)

echo "-- header --"
decode_jwt_part "${USER_JWT}" 0
echo "-- payload --"
decode_jwt_part "${USER_JWT}" 1

python3 - "${USER_JWT}" <<'PY'
import json, sys, base64
jwt = sys.argv[1]
header, payload = jwt.split(".")[:2]
def load(part):
    pad = "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part + pad))
h, p = load(header), load(payload)
assert h.get("typ") == "at+jwt", f"header typ should be at+jwt, got {h.get('typ')}"
assert "typ" not in p, f"payload must not contain typ, got {p.get('typ')}"
details = p.get("authorization_details")
assert isinstance(details, list) and details, "authorization_details missing from JWT"
assert details[0].get("type") == "vault:path_access", details
print("ok: header typ=at+jwt, no payload typ, authorization_details present")
PY

echo
echo "== Vault accepts RAR token for read role =="
CODE=$(vault_get "${USER_JWT}" "${READ_PATH}")
echo "HTTP ${CODE}"
python3 -m json.tool /tmp/vault-rar-body.json | head -40
if [ "${CODE}" != "200" ]; then
  echo "FAIL: expected 200 reading ${READ_PATH}" >&2
  exit 1
fi

echo
echo "== Vault denies write role (not in this token's RAR) =="
CODE=$(vault_get "${USER_JWT}" "${WRITE_PATH}")
echo "HTTP ${CODE}"
python3 -m json.tool /tmp/vault-rar-body.json | head -40
if [ "${CODE}" = "200" ]; then
  echo "FAIL: write role should be denied for users.read RAR" >&2
  exit 1
fi

echo
echo "== mint with explicit authorization_details (admin, write path only) =="
AUTHZ='[{"type":"vault:path_access","path":"database/creds/user-mcp-write-role","capabilities":["read"]}]'
ADMIN_RESP=$(mint admin admin "openid users.write" --data-urlencode "authorization_details=${AUTHZ}")
ADMIN_JWT=$(printf '%s' "${ADMIN_RESP}" | json_field access_token)
decode_jwt_part "${ADMIN_JWT}" 1 | python3 -c 'import json,sys; p=json.load(sys.stdin); print(json.dumps(p.get("authorization_details"), indent=2))'

CODE=$(vault_get "${ADMIN_JWT}" "${WRITE_PATH}")
echo "write-role HTTP ${CODE}"
if [ "${CODE}" != "200" ]; then
  python3 -m json.tool /tmp/vault-rar-body.json | head -40
  echo "FAIL: expected 200 reading ${WRITE_PATH} with explicit RAR" >&2
  exit 1
fi

CODE=$(vault_get "${ADMIN_JWT}" "${READ_PATH}")
echo "read-role HTTP ${CODE} (should be denied — not in this RAR)"
if [ "${CODE}" = "200" ]; then
  echo "FAIL: read role should be denied when RAR only lists the write path" >&2
  exit 1
fi

echo
echo "PASS: Keycloak OIDC RAR tokens are accepted and enforced by Vault 2.1"
