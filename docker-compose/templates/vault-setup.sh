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
# The bound_subject enforces exactly the user-mcp SPIFFE ID.
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
# NOTE: jwt-spiffe is used below only by ai-agent-spiffe (vault-agent's own
# SPIFFE login). user-mcp's own Vault access no longer uses SPIFFE — see the
# "Vault 2.1 native Agentic IAM" section near the end of this script.

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

# ── Vault 2.1 native Agentic IAM (Agent Registry + OAuth Resource Server) ────
# Replaces the SPIFFE-workload-identity Vault login user-mcp previously used
# for its own DB-credential and Transform calls. The human user's own
# validated Keycloak access token is now presented directly as the Vault
# token (X-Vault-Token) on every request: Vault validates it inline against
# the OAuth Resource Server profile below (signature + issuer + audience via
# Keycloak's JWKS), resolves an identity/entity via an entity-alias keyed on
# (issuer, sub), and computes effective capabilities as that entity's own
# baseline ACL policies intersected with its Agent Registry ceiling policy.
# No login call, and no SPIFFE identity for user-mcp is needed for this flow.
#
# RAR (authorization_details / vault:path_access) IS required. Keycloak does
# not put RFC 9396 details into the JWT by itself (OID4VCI processors only
# echo them on the token-endpoint JSON body). The custom protocol mapper
# oidc-vault-jwt-compat-mapper (keycloak-providers/) does two things Vault
# needs:
#   1. drops the payload `typ` claim Keycloak always writes in
#      TokenManager.initToken() — Vault OAuth RS schema-rejects that body
#      claim. Header typ is set separately via the client attribute
#      access.token.header.type.rfc9068 = at+jwt (RFC 9068).
#   2. copies authorization_details into the JWT from the token request
#      (form param or PAR client-session note), or synthesizes
#      vault:path_access entries from users.read / users.write scopes.
# token-exchange/verify/authorization.py still uses Keycloak Authorization
# Services as the live PDP for which scope a request is granted.

# oauth-resource-server required a one-time activation pre-2.1 (beta); as of
# Vault 2.1 it's GA and the activation-flags entry is gone entirely — only
# attempt activation if this Vault version still lists the flag at all.
if vault read sys/activation-flags | grep -q "oauth-resource-server"; then
  vault read sys/activation-flags | grep "^activated" | grep -q "oauth-resource-server" \
    || vault write -f sys/activation-flags/oauth-resource-server/activate
  echo "vault-setup: oauth-resource-server feature activated."
else
  echo "vault-setup: oauth-resource-server is GA on this Vault version, no activation needed."
fi

# Split-horizon issuer/JWKS, same pattern the old jwt-user-mcp mount used:
# Vault fetches JWKS from the internal Docker address, but tokens carry
# iss=http://localhost:8081/realms/demo.
vault write sys/config/oauth-resource-server/keycloak-demo \
  issuer_id="http://localhost:8081/realms/demo" \
  use_jwks=true \
  jwks_uri="http://keycloak:8080/realms/demo/protocol/openid-connect/certs" \
  user_claim="sub" \
  jwt_type="access_token" \
  audiences="user-mcp" \
  optional_authorization_details=false
echo "vault-setup: oauth-resource-server profile 'keycloak-demo' configured."

# Baseline/ceiling policies — same DB-creds + transform grants the old
# user-mcp-spiffe-read/write policies gave, just under the new naming.
vault policy write user-mcp-agentic-read - <<'EOF'
path "database/creds/user-mcp-read-role" {
  capabilities = ["read"]
}
path "transform/encode/user-mcp-transform" {
  capabilities = ["create", "update"]
}
EOF

vault policy write user-mcp-agentic-write - <<'EOF'
path "database/creds/user-mcp-write-role" {
  capabilities = ["read"]
}
path "transform/encode/user-mcp-transform" {
  capabilities = ["create", "update"]
}
EOF

# Look up the demo users' Keycloak ids (reuses the admin token already
# obtained above for the ai-agent id patch). Their `sub` claim equals this id.
echo "vault-setup: looking up demo user ids in Keycloak for agentic IAM entities..."
KC_READER_USER_ID=$(wget -qO- \
  --header="Authorization: Bearer ${KC_TOKEN}" \
  "http://keycloak:8080/admin/realms/demo/users?username=user&exact=true" \
  | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

KC_WRITER_USER_ID=$(wget -qO- \
  --header="Authorization: Bearer ${KC_TOKEN}" \
  "http://keycloak:8080/admin/realms/demo/users?username=admin&exact=true" \
  | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "vault-setup: keycloak user id (readers)=${KC_READER_USER_ID} admin id (readers+writers)=${KC_WRITER_USER_ID}"

# One Vault entity per demo persona, with baseline ACL policies matching
# their real Keycloak group (readers vs. readers+writers).
vault write identity/entity name=demo-user policies="user-mcp-agentic-read"
DEMO_USER_ENTITY_ID=$(vault read -field=id identity/entity/name/demo-user)

vault write identity/entity name=demo-admin policies="user-mcp-agentic-read,user-mcp-agentic-write"
DEMO_ADMIN_ENTITY_ID=$(vault read -field=id identity/entity/name/demo-admin)

# Entity aliases bind each entity to its Keycloak identity via (issuer, sub).
# `name` MUST equal the JWT `sub` — Vault looks the alias up by (issuer, name).
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

# Agent Registry ceiling policies — cap each entity to exactly the user-mcp
# DB-creds/transform grant appropriate to their persona.
vault write agent-registry/register \
  display_name="demo-user" \
  entity_id="${DEMO_USER_ENTITY_ID}" \
  ceiling_policies='["user-mcp-agentic-read"]'

vault write agent-registry/register \
  display_name="demo-admin" \
  entity_id="${DEMO_ADMIN_ENTITY_ID}" \
  ceiling_policies='["user-mcp-agentic-read","user-mcp-agentic-write"]'

echo "vault-setup: agentic IAM entities + agent registry registrations complete."

echo "vault-setup: done."
