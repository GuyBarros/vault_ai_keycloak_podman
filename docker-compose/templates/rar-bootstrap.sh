#!/bin/sh
# Minimal Vault 2.1 + Keycloak RAR bootstrap. Independent of SPIRE / LiteLLM
# so we can prove OIDC RAR without the rest of the demo stack.
set -e

echo "rar-bootstrap: waiting for Vault..."
until vault status >/dev/null 2>&1; do
  sleep 2
done

echo "rar-bootstrap: waiting for Keycloak demo realm..."
until wget -qO- http://keycloak:8080/realms/demo/.well-known/openid-configuration >/dev/null 2>&1; do
  sleep 3
done

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

if vault read sys/activation-flags >/dev/null 2>&1 && vault read sys/activation-flags | grep -q "oauth-resource-server"; then
  vault read sys/activation-flags | grep "^activated" | grep -q "oauth-resource-server" \
    || vault write -f sys/activation-flags/oauth-resource-server/activate
  echo "rar-bootstrap: oauth-resource-server feature activated."
else
  echo "rar-bootstrap: oauth-resource-server is GA on this Vault version, no activation needed."
fi

vault write sys/config/oauth-resource-server/keycloak-demo \
  issuer_id="http://localhost:8081/realms/demo" \
  use_jwks=true \
  jwks_uri="http://keycloak:8080/realms/demo/protocol/openid-connect/certs" \
  user_claim="sub" \
  jwt_type="access_token" \
  audiences="user-mcp" \
  optional_authorization_details=false
echo "rar-bootstrap: oauth-resource-server profile 'keycloak-demo' configured."

vault policy write user-mcp-agentic-read - <<'EOF'
path "database/creds/user-mcp-read-role" {
  capabilities = ["read"]
}
EOF

vault policy write user-mcp-agentic-write - <<'EOF'
path "database/creds/user-mcp-write-role" {
  capabilities = ["read"]
}
EOF

echo "rar-bootstrap: obtaining Keycloak admin token..."
KC_TOKEN=$(wget -qO- \
  --post-data="client_id=admin-cli&username=admin&password=admin&grant_type=password" \
  http://keycloak:8080/realms/master/protocol/openid-connect/token \
  | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

KC_READER_USER_ID=$(wget -qO- \
  --header="Authorization: Bearer ${KC_TOKEN}" \
  "http://keycloak:8080/admin/realms/demo/users?username=user&exact=true" \
  | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

KC_WRITER_USER_ID=$(wget -qO- \
  --header="Authorization: Bearer ${KC_TOKEN}" \
  "http://keycloak:8080/admin/realms/demo/users?username=admin&exact=true" \
  | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

echo "rar-bootstrap: keycloak user id=${KC_READER_USER_ID} admin id=${KC_WRITER_USER_ID}"

if [ -z "${KC_READER_USER_ID}" ] || [ -z "${KC_WRITER_USER_ID}" ]; then
  echo "rar-bootstrap: failed to resolve Keycloak user ids" >&2
  exit 1
fi

vault write identity/entity name=demo-user policies="user-mcp-agentic-read"
DEMO_USER_ENTITY_ID=$(vault read -field=id identity/entity/name/demo-user)

vault write identity/entity name=demo-admin policies="user-mcp-agentic-read,user-mcp-agentic-write"
DEMO_ADMIN_ENTITY_ID=$(vault read -field=id identity/entity/name/demo-admin)

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

vault write agent-registry/register \
  display_name="demo-user" \
  entity_id="${DEMO_USER_ENTITY_ID}" \
  ceiling_policies='["user-mcp-agentic-read"]'

vault write agent-registry/register \
  display_name="demo-admin" \
  entity_id="${DEMO_ADMIN_ENTITY_ID}" \
  ceiling_policies='["user-mcp-agentic-read","user-mcp-agentic-write"]'

echo "rar-bootstrap: done."
