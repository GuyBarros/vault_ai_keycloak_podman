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

# ── JWT auth backend for user-mcp SPIFFE workload identity ───────────────────
# SPIRE's JWKS endpoint is used so Vault can verify JWT-SVIDs issued by SPIRE.
# Only the TransformMasker (PII masking) still authenticates via SPIFFE.
# Database credentials are now obtained via the jwt-keycloak mount below.
vault auth list | grep -q "^jwt-spiffe/" || \
  vault auth enable -path=jwt-spiffe jwt

# Wait for the JWKS proxy (which fetches from SPIRE and serves clean JWKS).
echo "vault-setup: waiting for JWKS proxy..."
until wget -qO- http://jwks-proxy:19876 >/dev/null 2>&1; do
  sleep 2
done
echo "vault-setup: JWKS proxy is up."

# Configure the JWT auth mount to fetch JWKS from the persistent proxy.
# No bound_issuer — SPIRE JWT-SVIDs do not include an iss claim by default.
vault write auth/jwt-spiffe/config \
  jwks_url="http://jwks-proxy:19876" \
  jwt_supported_algs="RS256,ES256,ES384,RS512,PS256,PS384,PS512"

echo "vault-setup: jwt-spiffe config written (JWKS from proxy)."

# Policy: SPIFFE workload gets transform encode only (DB creds moved to jwt-keycloak).
vault policy write user-mcp-spiffe-transform - <<'EOF'
path "transform/encode/user-mcp-transform" {
  capabilities = ["create", "update"]
}
EOF

# JWT role bound to the user-mcp SPIFFE ID — transform only.
vault write auth/jwt-spiffe/role/user-mcp-spiffe-transform - <<'EOF'
{
  "role_type": "jwt",
  "user_claim": "sub",
  "bound_audiences": ["user_mcp"],
  "bound_subject": "spiffe://example.org/user-mcp",
  "bound_claims": {
    "sub": "spiffe://example.org/user-mcp"
  },
  "token_policies": ["user-mcp-spiffe-transform"],
  "token_ttl": 300,
  "token_max_ttl": 900,
  "token_type": "service"
}
EOF

# ── JWT auth backend for user-mcp OBO token (Keycloak-issued) ────────────────
# user-mcp authenticates to Vault with the caller's Keycloak OBO token
# (audience=user-mcp) to obtain short-lived database credentials.
# bound_claims enforce that the token was issued for the user-mcp audience,
# by the token-exchange client (azp), and carries the expected scope.
vault auth list | grep -q "^jwt-keycloak/" || \
  vault auth enable -path=jwt-keycloak jwt

vault write auth/jwt-keycloak/config \
  jwks_url="http://keycloak:8080/realms/demo/protocol/openid-connect/certs" \
  bound_issuer="http://localhost:8081/realms/demo" \
  jwt_supported_algs="RS256"

echo "vault-setup: jwt-keycloak config written (JWKS from Keycloak)."

# Policy: OBO-authenticated token gets DB read creds.
vault policy write user-mcp-obo-read - <<'EOF'
path "database/creds/user-mcp-read-role" {
  capabilities = ["read"]
}
EOF

# Policy: OBO-authenticated token gets DB write creds.
vault policy write user-mcp-obo-write - <<'EOF'
path "database/creds/user-mcp-write-role" {
  capabilities = ["read"]
}
EOF

# Role for OBO tokens that carry users.read scope.
# bound_claims enforce:
#   - aud contains "user-mcp"        (token was issued for this service)
#   - azp is "token-exchange"        (token was issued by the exchange client)
#   - scope contains "users.read"    (caller holds read entitlement)
# The scope claim is a space-separated string (e.g. "delegation:ai-agent users.read"),
# so a glob wildcard prefix/suffix is required for substring matching.
vault write auth/jwt-keycloak/role/user-mcp-obo-read - <<'EOF'
{
  "role_type": "jwt",
  "user_claim": "preferred_username",
  "bound_audiences": ["user-mcp"],
  "bound_claims": {
    "azp": "token-exchange",
    "scope": "*users.read*"
  },
  "bound_claims_type": "glob",
  "token_policies": ["user-mcp-obo-read"],
  "token_ttl": 300,
  "token_max_ttl": 900,
  "token_type": "service"
}
EOF

# Role for OBO tokens that carry users.write scope.
vault write auth/jwt-keycloak/role/user-mcp-obo-write - <<'EOF'
{
  "role_type": "jwt",
  "user_claim": "preferred_username",
  "bound_audiences": ["user-mcp"],
  "bound_claims": {
    "azp": "token-exchange",
    "scope": "*users.write*"
  },
  "bound_claims_type": "glob",
  "token_policies": ["user-mcp-obo-write"],
  "token_ttl": 300,
  "token_max_ttl": 900,
  "token_type": "service"
}
EOF

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
# The jwt-spiffe mount is already configured above for user-mcp; we reuse it
# and add a dedicated role bound to the ai-agent SPIFFE ID.

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

# Policy to allow user-mcp to encode through Transform
vault policy write user-mcp-transform - <<'EOF'
path "transform/encode/user-mcp-transform" {
  capabilities = ["create", "update"]
}
EOF

echo "vault-setup: done."
