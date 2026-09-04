#!/bin/sh
# Prove Vault jwt-keycloak bound_claims AND that SPIFFE remains as
# workload attestation without minting database/creds by itself.
set -eu

KC_URL="${KC_URL:-http://localhost:8081}"
VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
CLIENT_ID="${CLIENT_ID:-token-exchange}"
CLIENT_SECRET="${CLIENT_SECRET:-token-exchange-secret}"

pass=0
fail=0

kc_token() {
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

vault_login_host() {
  _jwt=$1
  _role=$2
  curl -sS -o /tmp/vault-login-body -w "%{http_code}" \
    -X POST "${VAULT_ADDR}/v1/auth/jwt-keycloak/login" \
    -H "Content-Type: application/json" \
    -d "{\"role\":\"${_role}\",\"jwt\":\"${_jwt}\"}"
}

expect() {
  _label=$1
  _got=$2
  _want=$3
  case ",${_want}," in
    *",${_got},"*)
      echo "PASS  ${_label} (http ${_got})"
      pass=$((pass + 1))
      ;;
    *)
      echo "FAIL  ${_label} (http ${_got}, expected ${_want})"
      echo "      body: $(head -c 400 /tmp/vault-login-body 2>/dev/null || true)"
      fail=$((fail + 1))
      ;;
  esac
}

echo "Minting Keycloak tokens..."
USER_READ=$(kc_token user user "users.read")
USER_WRITE_SCOPE=$(kc_token user user "users.write")
ADMIN_READ=$(kc_token admin admin "users.read")
ADMIN_WRITE=$(kc_token admin admin "users.write")

echo "--- jwt-keycloak bound_claims (from user-mcp) ---"
STATUS=$(vault_login_mcp "${USER_READ}" user-mcp-oidc-read)
expect "reader + users.read → oidc-read" "${STATUS}" "200"

STATUS=$(vault_login_mcp "${USER_READ}" user-mcp-oidc-write)
expect "reader + users.read → oidc-write (deny)" "${STATUS}" "400,403"

STATUS=$(vault_login_mcp "${USER_WRITE_SCOPE}" user-mcp-oidc-write)
expect "reader + users.write → oidc-write (deny groups)" "${STATUS}" "400,403"

STATUS=$(vault_login_mcp "${ADMIN_READ}" user-mcp-oidc-read)
expect "writer + users.read → oidc-read" "${STATUS}" "200"

STATUS=$(vault_login_mcp "${ADMIN_WRITE}" user-mcp-oidc-write)
expect "writer + users.write → oidc-write" "${STATUS}" "200"

STATUS=$(vault_login_mcp "${ADMIN_WRITE}" user-mcp-oidc-read)
expect "writer + users.write → oidc-read (deny scope)" "${STATUS}" "400,403"

echo "--- stolen OBO from host must not login ---"
STATUS=$(vault_login_host "${USER_READ}" user-mcp-oidc-read)
expect "host + valid reader JWT → oidc-read (deny CIDR)" "${STATUS}" "400,403"

echo "--- SPIFFE workload role (attestation only, no secrets) ---"
SPIFFE_ROLE=$(curl -sS -o /tmp/vault-login-body -w "%{http_code}" \
  -H "X-Vault-Token: root" \
  "${VAULT_ADDR}/v1/auth/jwt-spiffe/role/user-mcp-spiffe")
expect "jwt-spiffe user-mcp-spiffe role exists" "${SPIFFE_ROLE}" "200"
python3 - <<'PY'
import json, sys
body = json.load(open("/tmp/vault-login-body"))
data = body.get("data") or body
policies = data.get("token_policies") or []
if "user-mcp-oidc-read" in policies or "user-mcp-oidc-write" in policies:
    raise SystemExit("SPIFFE workload role must not carry OIDC DB policies")
if "user-mcp-transform" in policies:
    raise SystemExit("SPIFFE workload role must not carry transform policy")
if any("database" in str(p) for p in policies):
    raise SystemExit("SPIFFE workload role must not mention database policies")
print("PASS  SPIFFE workload role has no secret policy (token_policies=%s)" % policies)
PY
pass=$((pass + 1))

OIDC_ROLE=$(curl -sS -o /tmp/vault-login-body -w "%{http_code}" \
  -H "X-Vault-Token: root" \
  "${VAULT_ADDR}/v1/auth/jwt-keycloak/role/user-mcp-oidc-read")
expect "jwt-keycloak user-mcp-oidc-read role exists" "${OIDC_ROLE}" "200"
python3 - <<'PY'
import json
body = json.load(open("/tmp/vault-login-body"))
data = body.get("data") or body
policies = data.get("token_policies") or []
if "user-mcp-oidc-read" in policies or "user-mcp-oidc-write" in policies:
    raise SystemExit("human JWT login must not carry database/creds policy")
if "user-mcp-transform" in policies:
    raise SystemExit("human JWT login must not carry transform policy")
if "user-mcp-mint-action-read" not in policies:
    raise SystemExit("human JWT login must only mint the action identity, got %s" % policies)
print("PASS  jwt-keycloak oidc-read is mint-only (token_policies=%s)" % policies)
PY
pass=$((pass + 1))

echo "--- only the combined action token can mint DB creds ---"
USER_READ="$USER_READ" python3 - <<'PY'
import json, os, subprocess, urllib.parse, urllib.request, sys

user_read = os.environ["USER_READ"]

code = r'''
import json, os, urllib.request, urllib.error

def req(method, path, payload=None, token=None):
    headers = {}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode()
    if token:
        headers["X-Vault-Token"] = token
    r = urllib.request.Request("http://vault:8200/v1/" + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

st, body = req("POST", "auth/jwt-keycloak/login", {"role": "user-mcp-oidc-read", "jwt": os.environ["V_JWT"]})
parent = (body.get("auth") or {}).get("client_token")
print("OIDC_LOGIN", st)
if st != 200 or not parent:
    print("OIDC_CREDS", 0)
    print("ACTION_CREATE", 0)
    print("ACTION_CREDS", 0)
    print("ACTION_DISPLAY", "")
    raise SystemExit(0)
st, body = req("GET", "database/creds/user-mcp-read-role", token=parent)
print("OIDC_CREDS", st)
st, body = req("POST", "auth/token/create/user-mcp-action-read", {
    "display_name": "user+user-mcp",
    "meta": {"preferred_username": "user", "spiffe_id": "spiffe://example.org/user-mcp"},
    "ttl": "60s",
    "renewable": False,
}, token=parent)
print("ACTION_CREATE", st)
action = (body.get("auth") or {}).get("client_token")
if st != 200 or not action:
    print("ACTION_CREDS", 0)
    print("ACTION_DISPLAY", "")
    raise SystemExit(0)
st, body = req("GET", "database/creds/user-mcp-read-role", token=action)
print("ACTION_CREDS", st)
st, lookup = req("GET", "auth/token/lookup-self", token=action)
print("ACTION_DISPLAY", (lookup.get("data") or {}).get("display_name", ""))
'''

r = subprocess.run(
    ["docker", "exec", "-e", f"V_JWT={user_read}", "user-mcp", "/app/.venv/bin/python", "-c", code],
    capture_output=True, text=True,
)
out = r.stdout
print(out)
if r.returncode != 0:
    print(r.stderr)
    raise SystemExit("action-token prove helper failed")
vals = dict(line.split(" ", 1) for line in out.strip().splitlines() if " " in line)
if vals.get("OIDC_LOGIN") != "200":
    raise SystemExit("oidc login from user-mcp failed")
if vals.get("OIDC_CREDS") not in ("400", "403"):
    raise SystemExit("human JWT login must not mint DB creds, got %s" % vals.get("OIDC_CREDS"))
print("PASS  human jwt-keycloak token cannot read database/creds (http %s)" % vals.get("OIDC_CREDS"))
if vals.get("ACTION_CREATE") != "200":
    raise SystemExit("Vault did not mint combined action token, got %s" % vals.get("ACTION_CREATE"))
print("PASS  Vault minted combined action token (http 200)")
if vals.get("ACTION_CREDS") != "200":
    raise SystemExit("action token could not read database/creds, got %s" % vals.get("ACTION_CREDS"))
print("PASS  combined action token reads database/creds (http 200)")
display = vals.get("ACTION_DISPLAY", "")
if "user-mcp" not in display:
    raise SystemExit("action token display_name should include user-mcp, got %r" % display)
print("PASS  action token display_name=%s" % display)
PY
pass=$((pass + 4))

echo "--- leftover SPIFFE DB roles must not exist ---"
SPIFFE_WRITE=$(curl -sS -o /tmp/vault-login-body -w "%{http_code}" \
  -X POST "${VAULT_ADDR}/v1/auth/jwt-spiffe/login" \
  -H "Content-Type: application/json" \
  -d "{\"role\":\"user-mcp-spiffe-write\",\"jwt\":\"${USER_READ}\"}")
expect "jwt-spiffe user-mcp-spiffe-write gone" "${SPIFFE_WRITE}" "400,403,404"

echo
echo "Result: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
