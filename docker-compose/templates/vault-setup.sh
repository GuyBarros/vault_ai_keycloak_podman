#!/bin/sh
set -e

vault secrets list | grep -q "^database/" || vault secrets enable database

vault write database/config/users-db \
  plugin_name=postgresql-database-plugin \
  allowed_roles="user-mcp-read-role,user-mcp-write-role" \
  connection_url="postgresql://{{username}}:{{password}}@postgres:5432/users?sslmode=disable" \
  username=postgres \
  password=postgres

user_mcp_read_creation_stmt=$(cat <<'SQL'
CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
GRANT CONNECT ON DATABASE users TO "{{name}}";
GRANT USAGE ON SCHEMA public TO "{{name}}";
GRANT SELECT ON users TO "{{name}}";
SQL
)

user_mcp_write_creation_stmt=$(cat <<'SQL'
CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
GRANT CONNECT ON DATABASE users TO "{{name}}";
GRANT USAGE ON SCHEMA public TO "{{name}}";
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO "{{name}}";
GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO "{{name}}";
SQL
)

revoke_privileges=$(cat <<'SQL'
REVOKE ALL PRIVILEGES ON users FROM "{{name}}"; 
REVOKE ALL PRIVILEGES ON SCHEMA public FROM "{{name}}"; 
REVOKE CONNECT ON DATABASE users FROM "{{name}}"; 
DROP ROLE IF EXISTS "{{name}}"; 
SQL
)

vault write database/roles/user-mcp-read-role \
  db_name=users-db \
  creation_statements="${user_mcp_read_creation_stmt}" \
  revocation_statements="${revoke_privileges}" \
  default_ttl=1h \
  max_ttl=24h


vault write database/roles/user-mcp-write-role \
  db_name=users-db \
  creation_statements="${user_mcp_write_creation_stmt}" \
  revocation_statements="${revoke_privileges}" \
  default_ttl=1h \
  max_ttl=24h

# ── JWT auth backend for SPIFFE workload identity ────────────────────────────
# Used by ai-agent (actor token), by user-mcp on every DB-cred request
# (workload attestation), and by user-mcp Transform (PII masking).
# SPIFFE login never grants database/creds — that requires the human
# Keycloak OBO token on jwt-keycloak below.
vault auth list | grep -q "^jwt-spiffe/" || \
  vault auth enable -path=jwt-spiffe jwt

# Wait for the JWKS proxy (which fetches from SPIRE and serves clean JWKS).
echo "vault-setup: waiting for JWKS proxy..."
until wget -qO- http://jwks-proxy:19876 >/dev/null 2>&1; do
  sleep 2
done
echo "vault-setup: JWKS proxy is up."

# Configure the JWT auth mount to fetch JWKS from the persistent proxy.
# The proxy strips SPIRE-specific fields that cause Vault's parser to fail.
# No bound_issuer — SPIRE JWT-SVIDs do not include an iss claim by default.
# We enforce identity through bound_subject (the SPIFFE ID) in each role.
vault write auth/jwt-spiffe/config \
  jwks_url="http://jwks-proxy:19876" \
  jwt_supported_algs="RS256,ES256,ES384,RS512,PS256,PS384,PS512"

echo "vault-setup: jwt-spiffe config written (JWKS from proxy)."

vault policy write user-mcp-spiffe-authorize - <<'EOF'
path "sys/control-group/authorize" {
  capabilities = ["create", "update"]
}
path "sys/control-group/request" {
  capabilities = ["create", "update"]
}
EOF

# Drop legacy user-mcp SPIFFE roles that could mint DB creds from workload
# identity alone (no human bound_claims). Workload + transform roles follow.
vault delete auth/jwt-spiffe/role/user-mcp-spiffe-read >/dev/null 2>&1 || true
vault delete auth/jwt-spiffe/role/user-mcp-spiffe-write >/dev/null 2>&1 || true

# Workload attestation + control-group approval for the action token.
# No secrets and no token-role mint — those stay on the combined identity.
vault write auth/jwt-spiffe/role/user-mcp-spiffe - <<'EOF'
{
  "role_type": "jwt",
  "user_claim": "sub",
  "bound_audiences": ["TESTING"],
  "bound_subject": "spiffe://example.org/user-mcp",
  "token_policies": ["default", "user-mcp-spiffe-authorize"],
  "token_bound_cidrs": ["172.28.0.20/32"],
  "token_ttl": 300,
  "token_max_ttl": 900,
  "token_type": "service"
}
EOF

echo "vault-setup: jwt-spiffe user-mcp workload role written (authorize only)."

# ── JWT auth backend for Keycloak OBO tokens (human authorization) ───────────
# user-mcp presents the caller's OBO JWT. Vault validates signature, audience,
# issuer, and bound_claims (Keycloak groups + OIDC scope). The login token
# itself has NO database/creds or transform policy — it may only mint the
# combined action identity below. A reader token cannot assume the write mint
# role even if the workload asks for it.
vault auth list | grep -q "^jwt-keycloak/" || \
  vault auth enable -path=jwt-keycloak jwt

echo "vault-setup: waiting for Keycloak JWKS..."
until wget -qO- http://keycloak:8080/realms/demo/protocol/openid-connect/certs >/dev/null 2>&1; do
  sleep 2
done
echo "vault-setup: Keycloak JWKS is up."

# Tokens carry iss=http://localhost:8081/realms/demo (KC_HOSTNAME). JWKS is
# fetched over the Docker network; bound_issuer must match the public iss.
vault write auth/jwt-keycloak/config \
  jwks_url="http://keycloak:8080/realms/demo/protocol/openid-connect/certs" \
  bound_issuer="http://localhost:8081/realms/demo" \
  jwt_supported_algs="RS256"

# Secret policies attach ONLY to the combined action token roles, never to
# the human JWT login or the SPIFFE workload login.
vault policy write user-mcp-oidc-read - <<'EOF'
path "database/creds/user-mcp-read-role" {
  capabilities = ["read"]
}
EOF

vault policy write user-mcp-oidc-write - <<'EOF'
path "database/creds/user-mcp-write-role" {
  capabilities = ["read"]
}
EOF

# Written here so action token roles can reference it; engine is enabled later.
vault policy write user-mcp-transform - <<'EOF'
path "transform/encode/user-mcp-transform" {
  capabilities = ["create", "update"]
}
EOF

vault policy write user-mcp-mint-action-read - <<'EOF'
path "auth/token/create/user-mcp-action-read" {
  capabilities = ["update"]
  control_group = {
    ttl = "2m"
    factor "user-mcp-workload" {
      identity {
        group_names = ["user-mcp-workload"]
        approvals = 1
      }
    }
  }
}
EOF

vault policy write user-mcp-mint-action-write - <<'EOF'
path "auth/token/create/user-mcp-action-write" {
  capabilities = ["update"]
  control_group = {
    ttl = "2m"
    factor "user-mcp-workload" {
      identity {
        group_names = ["user-mcp-workload"]
        approvals = 1
      }
    }
  }
}
EOF

# SPIFFE login may only approve a pending action-token mint. No secrets,
# no token-role create. That is the Vault AND: human requests, workload
# authorizes, unwrap yields the combined action identity.
vault policy write user-mcp-spiffe-authorize - <<'EOF'
path "sys/control-group/authorize" {
  capabilities = ["create", "update"]
}
path "sys/control-group/request" {
  capabilities = ["create", "update"]
}
EOF

# CIBA is tied to the action, then to the actor on that action.
# OpenShell: silent OBO (Jira-like) vs HITL by condition of the action
# (create/delete like a refund; update stays silent unless the email is
# a sensitive/patient analogue).
#   deny on ciba/<action>/<username> = silent OBO
#   read on ciba/<action>/<username> = that human must Approve
vault policy write ciba-list-users - <<'EOF'
path "ciba/list-users/admin" {
  capabilities = ["deny"]
}
path "ciba/list-users/user" {
  capabilities = ["deny"]
}
path "ciba/list_all_users/admin" {
  capabilities = ["deny"]
}
path "ciba/list_all_users/user" {
  capabilities = ["deny"]
}
path "ciba/search_users_by_first_name/admin" {
  capabilities = ["deny"]
}
path "ciba/search_users_by_first_name/user" {
  capabilities = ["deny"]
}
path "sys/capabilities-self" {
  capabilities = ["update"]
}
EOF

vault policy write ciba-write - <<'EOF'
path "ciba/write/admin" {
  capabilities = ["read"]
}
path "ciba/write/user" {
  capabilities = ["read"]
}
path "ciba/create_user/admin" {
  capabilities = ["read"]
}
path "ciba/create_user/user" {
  capabilities = ["read"]
}
path "ciba/delete_user_by_email/admin" {
  capabilities = ["read"]
}
path "ciba/delete_user_by_email/user" {
  capabilities = ["read"]
}
path "ciba/update_user_by_email/admin" {
  capabilities = ["deny"]
}
path "ciba/update_user_by_email/user" {
  capabilities = ["deny"]
}
path "ciba/sensitive/admin" {
  capabilities = ["read"]
}
path "ciba/sensitive/user" {
  capabilities = ["read"]
}
path "sys/capabilities-self" {
  capabilities = ["update"]
}
EOF

# Third identity: Vault-issued action token = human (OBO) + workload (user-mcp).
# Only these tokens may read database/creds or call Transform. The parent JWT
# logins cannot. bound_cidrs keeps use of the action token on user-mcp.
vault write auth/token/roles/user-mcp-action-read - <<'EOF'
{
  "allowed_policies": ["user-mcp-oidc-read", "user-mcp-transform"],
  "orphan": false,
  "renewable": false,
  "token_explicit_max_ttl": 60,
  "token_bound_cidrs": ["172.28.0.20/32"],
  "token_type": "service"
}
EOF

vault write auth/token/roles/user-mcp-action-write - <<'EOF'
{
  "allowed_policies": ["user-mcp-oidc-write", "user-mcp-transform"],
  "orphan": false,
  "renewable": false,
  "token_explicit_max_ttl": 60,
  "token_bound_cidrs": ["172.28.0.20/32"],
  "token_type": "service"
}
EOF

# bound_claims is AND across keys; list values are OR. glob so space-separated
# OIDC `scope` still matches when other scopes are present.
# writers may also read (list users); readers cannot login to the write role.
# token_bound_cidrs pins issued tokens (and login) to the user-mcp workload
# address — a laptop with a stolen OBO cannot mint the action identity.
# CIBA for writes is ACL policy ciba-write (per-tool, per-actor paths).
# create/delete = HITL; update is silent unless ciba/sensitive/<user> is read
# (patient-record analogue: admin@demo.com). Reads stay silent OBO
# (deny on ciba/list_all_users/<username>). token_policies includes
# the matching policy so each human can probe the switch after login.
vault write auth/jwt-keycloak/role/user-mcp-oidc-read - <<'EOF'
{
  "role_type": "jwt",
  "user_claim": "preferred_username",
  "bound_audiences": ["user-mcp"],
  "bound_claims_type": "glob",
  "bound_claims": {
    "groups": ["readers", "writers"],
    "scope": "*users.read*"
  },
  "token_policies": ["user-mcp-mint-action-read", "ciba-list-users"],
  "token_bound_cidrs": ["172.28.0.20/32"],
  "token_ttl": 300,
  "token_max_ttl": 900,
  "token_type": "service"
}
EOF

vault write auth/jwt-keycloak/role/user-mcp-oidc-write - <<'EOF'
{
  "role_type": "jwt",
  "user_claim": "preferred_username",
  "bound_audiences": ["user-mcp"],
  "bound_claims_type": "glob",
  "bound_claims": {
    "groups": ["writers"],
    "scope": "*users.write*"
  },
  "token_policies": ["user-mcp-mint-action-write", "ciba-write"],
  "token_bound_cidrs": ["172.28.0.20/32"],
  "token_ttl": 300,
  "token_max_ttl": 900,
  "token_type": "service"
}
EOF

echo "vault-setup: jwt-keycloak mint-only roles + action token roles written."

# Vault OIDC identity: issuer + role for the ai-agent ──
vault write identity/oidc/config \
  issuer="http://vault:8200"

# Create the OIDC signing key (dev mode does not guarantee it exists).
vault write identity/oidc/key/default \
  algorithm=RS256 \
  rotation_period=24h \
  verification_ttl=24h

# Create the OIDC role referencing that key.
vault write identity/oidc/role/agent-role \
  key=default \
  ttl=3600s \
  template="$(cat <<'EOF'
{
  "org": "ibm",
  "bu": "hr",
  "department": "payroll",
  "service_group": "employee-profile",
  "entity_id": "ai-agent",
  "agent_id": "ai-agent"
}
EOF
)"

# Policies
vault policy write agent-role-identity-policy - <<'EOF'
# Allow the agent to mint a Vault-signed OIDC token for itself
path "identity/oidc/token/agent-role" {
  capabilities = ["read"]
}
EOF

vault policy write opa - <<'EOF'
# Allow the OPA server to read the policy bundle
path "opa-policies/data/bundle" {
  capabilities = ["read"]
}
EOF

# SPIFFE JWT auth for the ai-agent (vault-agent authenticates via SPIRE SVID).
# The jwt-spiffe mount is already configured above; we add a dedicated role
# bound to the ai-agent SPIFFE ID.

vault policy write ai-agent-spiffe-policy - <<'EOF'
path "identity/oidc/token/agent-role" {
  capabilities = ["read"]
}
path "litellm/data/config" {
  capabilities = ["read"]
}
path "transform/encode/user-mcp-transform" {
  capabilities = ["create", "update"]
}
path "agent-lifecycle/data/ai-agent" {
  capabilities = ["read"]
}
path "agent-registry/registration/display-name/ai-agent" {
  capabilities = ["read"]
}
EOF

vault write auth/jwt-spiffe/role/ai-agent-spiffe - <<'EOF'
{
  "role_type": "jwt",
  "user_claim": "sub",
  "bound_audiences": ["TESTING"],
  "bound_subject": "spiffe://example.org/ai-agent",
  "token_policies": ["default", "ai-agent-spiffe-policy"],
  "token_period": 1800,
  "token_type": "service"
}
EOF

vault policy write ai-agent-child-spiffe-policy - <<'EOF'
path "identity/oidc/token/child-role" {
  capabilities = ["read"]
}
EOF

vault write auth/jwt-spiffe/role/ai-agent-child-spiffe - <<'EOF'
{
  "role_type": "jwt",
  "user_claim": "sub",
  "bound_audiences": ["TESTING"],
  "bound_subject": "spiffe://example.org/ai-agent-child",
  "token_policies": ["default", "ai-agent-child-spiffe-policy"],
  "token_period": 1800,
  "token_type": "service"
}
EOF

# Pre-create an Identity entity for the ai-agent so that tokens minted via
# jwt-spiffe login carry an entity ID.  Vault OIDC tokens (identity/oidc/token/*)
# require the calling token to be entity-bound; without this the token field
# in the response is empty.
vault write identity/entity \
  name=ai-agent \
  policies="default,ai-agent-spiffe-policy"

ENTITY_ID=$(vault read -field=id identity/entity/name/ai-agent)
echo "vault-setup: ai-agent entity id = ${ENTITY_ID}"

# Resolve the jwt-spiffe mount accessor and create an entity alias so the
# SPIFFE login maps to the ai-agent identity entity.
JWT_SPIFFE_ACCESSOR=$(vault auth list -detailed -format=table \
  | awk '/^jwt-spiffe\// {print $3}')
echo "vault-setup: jwt-spiffe accessor = ${JWT_SPIFFE_ACCESSOR}"
if [ -z "${JWT_SPIFFE_ACCESSOR}" ]; then
  echo "vault-setup: ERROR — could not resolve jwt-spiffe accessor" >&2
  exit 1
fi

vault write identity/entity name=user-mcp-workload
USER_MCP_ENTITY_ID=$(vault read -field=id identity/entity/name/user-mcp-workload)
echo "vault-setup: user-mcp workload entity id = ${USER_MCP_ENTITY_ID}"

vault write identity/entity-alias \
  name="spiffe://example.org/user-mcp" \
  canonical_id="${USER_MCP_ENTITY_ID}" \
  mount_accessor="${JWT_SPIFFE_ACCESSOR}" \
  || echo "vault-setup: user-mcp entity-alias already present (ok on re-run)."

vault write identity/group \
  name=user-mcp-workload \
  type=internal \
  member_entity_ids="${USER_MCP_ENTITY_ID}"
echo "vault-setup: identity group user-mcp-workload written."

vault write identity/entity-alias \
  name="spiffe://example.org/ai-agent" \
  canonical_id="${ENTITY_ID}" \
  mount_accessor="${JWT_SPIFFE_ACCESSOR}"

# ── Patch Keycloak ai-agent user id to match the Vault entity UUID ────────────
# Vault OIDC tokens always use the entity UUID as sub. Keycloak's delegation
# token-exchange validates actor_token.sub against the actor user's id.
# We update the Keycloak user id to the Vault entity UUID so they match.
# curl is required for the PUT call — install it transiently via apk.
apk add --no-cache curl jq >/dev/null 2>&1

echo "vault-setup: obtaining Keycloak admin token..."
KC_TOKEN=$(wget -qO- \
  --post-data="client_id=admin-cli&username=admin&password=admin&grant_type=password" \
  http://keycloak:8080/realms/master/protocol/openid-connect/token \
  | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

echo "vault-setup: looking up ai-agent user in Keycloak..."
KC_USER_ID=$(wget -qO- \
  --header="Authorization: Bearer ${KC_TOKEN}" \
  "http://keycloak:8080/admin/realms/demo/users?username=ai-agent&exact=true" \
  | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "vault-setup: keycloak ai-agent user id = ${KC_USER_ID}"

# Fetch the full user object then replace the id field and PUT it back.
KC_USER_JSON=$(wget -qO- \
  --header="Authorization: Bearer ${KC_TOKEN}" \
  "http://keycloak:8080/admin/realms/demo/users/${KC_USER_ID}")

UPDATED_JSON=$(echo "${KC_USER_JSON}" | sed "s/\"id\":\"${KC_USER_ID}\"/\"id\":\"${ENTITY_ID}\"/")

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X PUT \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "${UPDATED_JSON}" \
  "http://keycloak:8080/admin/realms/demo/users/${KC_USER_ID}")

if [ "${HTTP_STATUS}" = "204" ]; then
  echo "vault-setup: Keycloak ai-agent user id updated to ${ENTITY_ID}"
else
  echo "vault-setup: WARNING — failed to update Keycloak ai-agent user id (HTTP ${HTTP_STATUS})" >&2
fi

# RFC 8693 may_act.sub must be the SPIFFE ID (same string as act.sub / Vault
# OAuth alias). The parameterized user-property mapper copies Keycloak user
# id, which is either "ai-agent" or the Vault entity UUID — never SPIFFE —
# because token-exchange-delegation matches actor_token.sub to that user id.
echo "vault-setup: setting may_act.sub to SPIFFE on client scope delegation..."
DELEGATION_SCOPE_ID=$(curl -sS \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  "http://keycloak:8080/admin/realms/demo/client-scopes" \
  | jq -r '.[] | select(.name=="delegation") | .id')
MAY_ACT_MAPPER=$(curl -sS \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  "http://keycloak:8080/admin/realms/demo/client-scopes/${DELEGATION_SCOPE_ID}/protocol-mappers/models" \
  | jq -c '.[] | select(.name=="may_act sub")')
MAY_ACT_MAPPER_ID=$(printf '%s' "${MAY_ACT_MAPPER}" | jq -r '.id')
MAY_ACT_UPDATED=$(printf '%s' "${MAY_ACT_MAPPER}" | jq -c \
  --arg v "spiffe://example.org/ai-agent" \
  '.protocolMapper="oidc-hardcoded-claim-mapper"
   | .config["claim.value"]=$v
   | .config["claim.name"]="may_act.sub"
   | .config["jsonType.label"]="String"
   | .config["access.token.claim"]="true"
   | .config["id.token.claim"]="true"
   | .config["introspection.token.claim"]="true"
   | del(.config["user.attribute"], .config["multivalued"])')
MAY_ACT_HTTP=$(curl -sS -o /dev/null -w "%{http_code}" \
  -X PUT \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "${MAY_ACT_UPDATED}" \
  "http://keycloak:8080/admin/realms/demo/client-scopes/${DELEGATION_SCOPE_ID}/protocol-mappers/models/${MAY_ACT_MAPPER_ID}")
if [ "${MAY_ACT_HTTP}" = "204" ]; then
  echo "vault-setup: may_act.sub = spiffe://example.org/ai-agent"
else
  echo "vault-setup: WARNING — failed to set may_act.sub SPIFFE (HTTP ${MAY_ACT_HTTP})" >&2
fi

echo "vault-setup: enabling OIDC backchannel logout on client web..."
WEB_CLIENT=$(curl -sS \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  "http://keycloak:8080/admin/realms/demo/clients?clientId=web")
WEB_ID=$(printf '%s' "${WEB_CLIENT}" | jq -r '.[0].id')
WEB_BODY=$(curl -sS \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  "http://keycloak:8080/admin/realms/demo/clients/${WEB_ID}")
WEB_UPDATED=$(printf '%s' "${WEB_BODY}" | jq -c \
  '.attributes["backchannel.logout.url"]="http://web:8080/api/auth/backchannel-logout"
   | .attributes["backchannel.logout.session.required"]="true"')
WEB_HTTP=$(curl -sS -o /dev/null -w "%{http_code}" \
  -X PUT \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "${WEB_UPDATED}" \
  "http://keycloak:8080/admin/realms/demo/clients/${WEB_ID}")
if [ "${WEB_HTTP}" = "204" ]; then
  echo "vault-setup: web backchannel.logout.url set"
else
  echo "vault-setup: WARNING — failed to set backchannel logout (HTTP ${WEB_HTTP})" >&2
fi

# KV v2 secrets for LiteLLM
vault secrets list | grep -q "^litellm/" || \
  vault secrets enable -path=litellm -version=2 kv

vault kv put litellm/config \
  openai_api_key="${OPENAI_API_KEY:-}" \
  anthropic_api_key="${ANTHROPIC_API_KEY:-}" \
  watsonx_api_key="${WATSONX_API_KEY:-}" \
  watsonx_project_id="${WATSONX_PROJECT_ID:-}" \
  master_key="${LITELLM_MASTER_KEY:-ibm123}"

vault policy write litellm-secrets - <<'EOF'
path "litellm/data/config" {
  capabilities = ["read"]
}
EOF

# ── Vault Transform Secret Engine (PII masking for user-mcp) ──────────────────
# Only the two builtin templates (socialsecuritynumber, creditcardnumber) are
# used for Vault Transform masking — custom regex templates are unreliable in
# this version. phone, email, and ip_address are masked in the application
# layer (vault_transform.py) without a Vault round-trip.
vault secrets list | grep -q "^transform/" || vault secrets enable transform

# SSN — uses Vault builtin template
vault write transform/transformation/mask-ssn \
  type=masking \
  template="builtin/socialsecuritynumber" \
  masking_character='*' \
  allowed_roles="user-mcp-transform"

# Credit card — uses Vault builtin template (strips non-digits before encoding)
vault write transform/transformation/mask-credit-card \
  type=masking \
  template="builtin/creditcardnumber" \
  masking_character='*' \
  allowed_roles="user-mcp-transform"

# Role that bundles only the two Vault-backed transformations
vault write transform/role/user-mcp-transform \
  transformations=mask-ssn,mask-credit-card

# Leftover SPIFFE transform role: attestation only. Transform encode is
# granted solely on the combined action token (user + user-mcp).
vault write auth/jwt-spiffe/role/user-mcp-spiffe-transform - <<'EOF'
{
  "role_type": "jwt",
  "user_claim": "sub",
  "bound_audiences": ["TESTING"],
  "bound_subject": "spiffe://example.org/user-mcp",
  "token_policies": ["default"],
  "token_bound_cidrs": ["172.28.0.20/32"],
  "token_ttl": 300,
  "token_max_ttl": 900,
  "token_type": "service"
}
EOF

# ── Vault 2.1 native Agentic IAM (OAuth Resource Server + Agent Registry) ──
# user-mcp presents the Keycloak OBO (or CIBA) JWT as X-Vault-Token. Vault
# validates it inline, resolves the human from `sub` and the actor from
# `act.sub` (when present), and intersects:
#   1. human baseline ACL
#   2. agent-registry ceiling on the actor (or on the human for CIBA tokens)
#   3. RFC 9396 authorization_details (vault:path_access)
# jwt-keycloak + SPIFFE action tokens stay for CIBA policy probe; secrets
# themselves are gated by this OAuth RS path.

# Native RAR (oauth-resource-server + Agent Registry) shipped in 2.0.3 behind
# an activation flag. Vault 2.1 made it GA and started requiring the Agentic
# IAM license term (post 2026-09-01). This demo stays on 2.0.4-ent so the
# current trial license can activate the flag. On 2.1+, skip activate and
# expect Feature Not Enabled unless the .hclic lists Agentic IAM.
if vault read sys/activation-flags >/dev/null 2>&1 && vault read sys/activation-flags | grep -q "oauth-resource-server"; then
  vault read sys/activation-flags | grep "^activated" | grep -q "oauth-resource-server" \
    || vault write -f sys/activation-flags/oauth-resource-server/activate
  echo "vault-setup: oauth-resource-server feature activated."
else
  echo "vault-setup: oauth-resource-server is GA on this Vault version, no activation needed."
fi

if vault write sys/config/oauth-resource-server/keycloak-demo \
  issuer_id="http://localhost:8081/realms/demo" \
  use_jwks=true \
  jwks_uri="http://keycloak:8080/realms/demo/protocol/openid-connect/certs" \
  user_claim="sub" \
  jwt_type="access_token" \
  audiences="user-mcp" \
  optional_authorization_details=false
then
  echo "vault-setup: oauth-resource-server profile 'keycloak-demo' configured."
else
  echo "vault-setup: failed to configure oauth-resource-server (need a Vault Enterprise license with Agentic IAM)." >&2
  vault read sys/license/status || true
  exit 1
fi

vault policy write user-mcp-agentic-read - <<'EOF'
path "database/creds/user-mcp-read-role" {
  capabilities = ["read"]
}
path "transform/encode/user-mcp-transform" {
  capabilities = ["create", "update"]
}
path "sys/leases/revoke" {
  capabilities = ["update"]
}
path "sys/capabilities-self" {
  capabilities = ["update"]
}
path "ciba/list-users/admin" {
  capabilities = ["deny"]
}
path "ciba/list-users/user" {
  capabilities = ["deny"]
}
path "ciba/list_all_users/admin" {
  capabilities = ["deny"]
}
path "ciba/list_all_users/user" {
  capabilities = ["deny"]
}
path "ciba/search_users_by_first_name/admin" {
  capabilities = ["deny"]
}
path "ciba/search_users_by_first_name/user" {
  capabilities = ["deny"]
}
path "ciba/write/admin" {
  capabilities = ["deny"]
}
path "ciba/write/user" {
  capabilities = ["deny"]
}
EOF

vault policy write user-mcp-agentic-write - <<'EOF'
path "database/creds/user-mcp-write-role" {
  capabilities = ["read"]
}
path "sys/leases/revoke" {
  capabilities = ["update"]
}
path "transform/encode/user-mcp-transform" {
  capabilities = ["create", "update"]
}
path "ciba/write/admin" {
  capabilities = ["read"]
}
path "ciba/write/user" {
  capabilities = ["read"]
}
path "ciba/create_user/admin" {
  capabilities = ["read"]
}
path "ciba/create_user/user" {
  capabilities = ["read"]
}
path "ciba/delete_user_by_email/admin" {
  capabilities = ["read"]
}
path "ciba/delete_user_by_email/user" {
  capabilities = ["read"]
}
path "ciba/update_user_by_email/admin" {
  capabilities = ["deny"]
}
path "ciba/update_user_by_email/user" {
  capabilities = ["deny"]
}
path "ciba/sensitive/admin" {
  capabilities = ["read"]
}
path "ciba/sensitive/user" {
  capabilities = ["read"]
}
EOF

echo "vault-setup: looking up demo user ids in Keycloak for agentic IAM entities..."
KC_READER_USER_ID=$(wget -qO- \
  --header="Authorization: Bearer ${KC_TOKEN}" \
  "http://keycloak:8080/admin/realms/demo/users?username=user&exact=true" \
  | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

KC_WRITER_USER_ID=$(wget -qO- \
  --header="Authorization: Bearer ${KC_TOKEN}" \
  "http://keycloak:8080/admin/realms/demo/users?username=admin&exact=true" \
  | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "vault-setup: keycloak user id=${KC_READER_USER_ID} admin id=${KC_WRITER_USER_ID}"

vault write identity/entity name=demo-user policies="user-mcp-agentic-read"
DEMO_USER_ENTITY_ID=$(vault read -field=id identity/entity/name/demo-user)

vault write identity/entity name=demo-admin policies="user-mcp-agentic-read,user-mcp-agentic-write"
DEMO_ADMIN_ENTITY_ID=$(vault read -field=id identity/entity/name/demo-admin)

# issuer= tells Vault to bind the alias to the OAuth resource-server profile.
vault write identity/entity-alias \
  name="${KC_READER_USER_ID}" \
  canonical_id="${DEMO_USER_ENTITY_ID}" \
  issuer="http://localhost:8081/realms/demo" \
  external_id="${KC_READER_USER_ID}"

vault write identity/entity-alias \
  name="${KC_WRITER_USER_ID}" \
  canonical_id="${DEMO_ADMIN_ENTITY_ID}" \
  issuer="http://localhost:8081/realms/demo" \
  external_id="${KC_WRITER_USER_ID}"

# CIBA tokens have no act claim — the human must be a registered agent.
# OBO tokens carry act.sub = SPIFFE ID (oauth-resource-server alias name).
# Repeat ceiling_policies= so the CLI sends a string slice (a JSON array string
# is split on commas and stored as garbage policy names).
register_agent() {
  _name=$1
  _entity=$2
  shift 2
  _id=$(vault read -field=id "agent-registry/registration/display-name/${_name}" 2>/dev/null || true)
  if [ -n "${_id}" ]; then
    vault write agent-registry/register id="${_id}" display_name="${_name}" entity_id="${_entity}" "$@"
  else
    vault write agent-registry/register display_name="${_name}" entity_id="${_entity}" "$@"
  fi
}

# One oauth-resource-server alias per entity+mount. Name it with the SPIFFE ID
# so Vault RS resolves act.sub the same way the video shows.
set_oauth_spiffe_alias() {
  _canonical=$1
  _spiffe=$2
  for _aid in $(vault list identity/entity-alias/id 2>/dev/null | awk 'NR>2 {print $1}'); do
    [ -z "${_aid}" ] && continue
    _info=$(vault read "identity/entity-alias/id/${_aid}" 2>/dev/null || true)
    echo "${_info}" | grep -q "${_canonical}" || continue
    echo "${_info}" | grep -q oauth-resource-server || continue
    _cur=$(echo "${_info}" | awk '/^name[ \t]/ {print $2; exit}')
    if [ "${_cur}" != "${_spiffe}" ]; then
      vault delete "identity/entity-alias/id/${_aid}" \
        || echo "vault-setup: could not delete leftover oauth alias ${_cur}"
    fi
  done
  vault write identity/entity-alias \
    name="${_spiffe}" \
    canonical_id="${_canonical}" \
    issuer="http://localhost:8081/realms/demo" \
    external_id="${_spiffe}" \
    || echo "vault-setup: oauth alias ${_spiffe} already present (ok on re-run)."
}

register_agent demo-user "${DEMO_USER_ENTITY_ID}" \
  owner=user \
  description="Demo reader identity" \
  ceiling_policies=user-mcp-agentic-read

register_agent demo-admin "${DEMO_ADMIN_ENTITY_ID}" \
  owner=admin \
  description="Demo writer identity" \
  ceiling_policies=user-mcp-agentic-read \
  ceiling_policies=user-mcp-agentic-write

register_agent ai-agent "${ENTITY_ID}" \
  owner=admin \
  description="Parent demo agent" \
  ceiling_policies=user-mcp-agentic-read \
  ceiling_policies=user-mcp-agentic-write

# Child sandbox: own SPIRE identity + narrower registry ceiling (read only).
vault write identity/entity name=ai-agent-child \
  policies="user-mcp-agentic-read,ai-agent-child-spiffe-policy"
CHILD_ENTITY_ID=$(vault read -field=id identity/entity/name/ai-agent-child)
register_agent ai-agent-child "${CHILD_ENTITY_ID}" \
  owner=admin \
  description="Child sandbox agent (read ceiling)" \
  ceiling_policies=user-mcp-agentic-read

vault write identity/entity-alias \
  name="spiffe://example.org/ai-agent-child" \
  canonical_id="${CHILD_ENTITY_ID}" \
  mount_accessor="${JWT_SPIFFE_ACCESSOR}" \
  || echo "vault-setup: ai-agent-child jwt-spiffe alias already present (ok on re-run)."

set_oauth_spiffe_alias "${CHILD_ENTITY_ID}" "spiffe://example.org/ai-agent-child"

vault write identity/oidc/role/child-role \
  key=default \
  ttl=3600s \
  template="$(cat <<'EOF'
{
  "org": "ibm",
  "bu": "hr",
  "department": "payroll",
  "service_group": "employee-profile",
  "entity_id": "ai-agent-child",
  "agent_id": "ai-agent-child",
  "parent_agent_id": "ai-agent"
}
EOF
)"

vault write identity/oidc/role/agent-role \
  key=default \
  ttl=3600s \
  template="$(cat <<'EOF'
{
  "org": "ibm",
  "bu": "hr",
  "department": "payroll",
  "service_group": "employee-profile",
  "entity_id": "ai-agent",
  "agent_id": "ai-agent"
}
EOF
)"

set_oauth_spiffe_alias "${ENTITY_ID}" "spiffe://example.org/ai-agent"

# Owner can suspend the agent: vault kv put agent-lifecycle/ai-agent enabled=false
vault secrets list | grep -q "^agent-lifecycle/" || \
  vault secrets enable -path=agent-lifecycle -version=2 kv
vault kv put agent-lifecycle/ai-agent enabled=true owner=admin onboarded=true

echo "vault-setup: agentic IAM entities + agent registry complete."

echo "vault-setup: done."
