declare namespace NodeJS {
  interface ProcessEnv {
    KEYCLOAK_CLIENT_ID: string;
    KEYCLOAK_CLIENT_SECRET: string;
    KEYCLOAK_BASE_URL: string;
    KEYCLOAK_INTERNAL_BASE_URL?: string;
    KEYCLOAK_REALM: string;
    KEYCLOAK_REDIRECT_URI: string;
    KEYCLOAK_LOGOUT_URI: string;
    KEYCLOAK_SCOPES?: string;
    AI_AGENT_API_URL?: string;
    AI_AGENT_DNS_RETRY_ATTEMPTS?: string;
    AI_AGENT_DNS_RETRY_BASE_DELAY_MS?: string;
    AI_AGENT_DNS_RETRY_MAX_DELAY_MS?: string;
    LOG_LEVEL?: string;
    LOG_SERVICE_NAME?: string;
    LOG_ENVIRONMENT?: string;
    COOKIE_SECURE?: string;
    SESSION_PASSWORD: string;
    NODE_ENV: 'development' | 'production' | 'test';
  }
}
