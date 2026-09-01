vault {
  address = "http://vault:8200"
  retry {
    num_retries = 5
  }
}

# Authenticate to Vault using a SPIFFE JWT-SVID.
# vault-agent-start.sh fetches the SVID from the SPIRE Workload API and writes
# it to /tmp/spire-jwt/svid.jwt; this method reads it from that file.
auto_auth {
  method "jwt" {
    mount_path = "auth/jwt-spiffe"
    config = {
      path                     = "/tmp/spire-jwt/svid.jwt"
      role                     = "ai-agent-spiffe"
      remove_jwt_after_reading = false
    }
  }
}

# Render the OIDC actor token to the shared in-memory volume.
template {
  contents     = "{{ with secret \"identity/oidc/token/agent-role\" }}{{ .Data.token }}{{ end }}"
  destination  = "/vault/secrets/actor-token"
  # Re-render whenever the lease is close to expiring (default: 1/3 of TTL).
  perms        = "0640"
}

# Render LiteLLM secrets as a shell env file consumed by the litellm container.
template {
  contents = <<EOF
{{- with secret "litellm/data/config" -}}
OPENAI_API_KEY={{ .Data.data.openai_api_key }}
WATSONX_API_KEY={{ .Data.data.watsonx_api_key }}
WATSONX_PROJECT_ID={{ .Data.data.watsonx_project_id }}
LITELLM_MASTER_KEY={{ .Data.data.master_key }}
{{- end }}
EOF
  destination = "/vault/secrets/litellm.env"
  perms       = "0644"
}
