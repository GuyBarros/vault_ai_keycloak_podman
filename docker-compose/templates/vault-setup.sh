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
  "token_policies": ["user-mcp-mint-action-read"],
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
  "token_policies": ["user-mcp-mint-action-write"],
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
apk add --no-cache curl >/dev/null 2>&1

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

# KV v2 secrets for LiteLLM
vault secrets list | grep -q "^litellm/" || \
  vault secrets enable -path=litellm -version=2 kv

vault kv put litellm/config \
  openai_api_key="${OPENAI_API_KEY:-}" \
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

echo "vault-setup: done."
