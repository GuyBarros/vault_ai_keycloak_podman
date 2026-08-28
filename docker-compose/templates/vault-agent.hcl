vault {
  address = "http://vault:8200"
  retry {
    num_retries = 5
  }
}

# AppRole credentials are written to the shared volume by vault-setup.
auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path                   = "/vault/creds/role-id"
      secret_id_file_path                 = "/vault/creds/secret-id"
      remove_secret_id_file_after_reading = false
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
