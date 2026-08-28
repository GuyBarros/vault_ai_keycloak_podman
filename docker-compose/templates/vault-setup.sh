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

# JWT auth backend for user-mcp (Keycloak as the OIDC provider) ──
# Keycloak OIDC discovery for the demo realm.
vault auth list | grep -q "^jwt-user-mcp/" || \
  vault auth enable -path=jwt-user-mcp jwt

# Split-horizon setup: Vault fetches JWKS from the internal Docker address
# (keycloak:8080) but tokens carry iss=http://localhost:8081/realms/demo
# jwks_url bypasses the oidc_discovery issuer-match check; bound_issuer then
# enforces the correct public issuer on every inbound token.
vault write auth/jwt-user-mcp/config \
  jwks_url="http://keycloak:8080/realms/demo/protocol/openid-connect/certs" \
  bound_issuer="http://localhost:8081/realms/demo"

# Policies for DB credential access
vault policy write user-mcp-db-read - <<'EOF'
path "database/creds/user-mcp-read-role" {
  capabilities = ["read"]
}
EOF

vault policy write user-mcp-db-write - <<'EOF'
path "database/creds/user-mcp-write-role" {
  capabilities = ["read"]
}
EOF

# JWT roles: bound to the "user-mcp" audience; realm_access.roles glob-matched.
# ***Keycloak places realm roles at realm_access.roles (array of strings).
vault write auth/jwt-user-mcp/role/user-mcp-read - <<'EOF'
{
  "role_type": "jwt",
  "user_claim": "preferred_username",
  "bound_audiences": ["user-mcp"],
  "bound_claims_type": "glob",
  "bound_claims": { "groups": "*readers*" },
  "token_policies": ["user-mcp-db-read"],
  "token_ttl": 300,
  "token_max_ttl": 900,
  "token_type": "service"
}
EOF

vault write auth/jwt-user-mcp/role/user-mcp-write - <<'EOF'
{
  "role_type": "jwt",
  "user_claim": "preferred_username",
  "bound_audiences": ["user-mcp"],
  "bound_claims_type": "glob",
  "bound_claims": { "groups": "*writers*" },
  "token_policies": ["user-mcp-db-write"],
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

# AppRole auth for the ai-agent (docker-compose — no K8s SA injector)
# Vault Agent natively supports the "approle" auto_auth method.
vault auth list | grep -q "^approle/" || vault auth enable approle

vault write auth/approle/role/ai-agent \
  token_policies="default,agent-role-identity-policy,litellm-secrets" \
  token_period=1800 \
  token_type=service \
  secret_id_ttl=0 \
  token_num_uses=0

# Pre-create an Identity entity for the ai-agent so that tokens minted via
# AppRole login have an entity ID.  Vault OIDC tokens (identity/oidc/token/*)
# require the calling token to be entity-bound; without this the token field
# in the response is empty.
vault write identity/entity \
  name=ai-agent \
  policies="default,agent-role-identity-policy,litellm-secrets"
# Read back the ID by name — vault read returns key=value lines, -field extracts cleanly.
ENTITY_ID=$(vault read -field=id identity/entity/name/ai-agent)

# Resolve the AppRole accessor using vault's own -field flag.
APPROLE_ACCESSOR=$(vault auth list -detailed -format=table \
  | awk '/^approle\// {print $3}')

# Create (or update) the entity alias that maps the AppRole mount to the entity.
ROLE_ID=$(vault read -field=role_id auth/approle/role/ai-agent/role-id)
vault write identity/entity-alias \
  name="${ROLE_ID}" \
  canonical_id="${ENTITY_ID}" \
  mount_accessor="${APPROLE_ACCESSOR}"

# Write role-id and secret-id to the shared volume so vault-agent can read them.
# Write to temp files first, then move atomically so vault-agent never sees an
# empty/partial file if the vault command fails mid-redirect.
vault read  -field=role_id   auth/approle/role/ai-agent/role-id      > /vault-agent-creds/role-id.tmp
vault write -f -field=secret_id auth/approle/role/ai-agent/secret-id > /vault-agent-creds/secret-id.tmp
mv /vault-agent-creds/role-id.tmp   /vault-agent-creds/role-id
mv /vault-agent-creds/secret-id.tmp /vault-agent-creds/secret-id

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

echo "vault-setup: done."
