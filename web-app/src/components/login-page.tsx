interface Props {
  error?: string;
}

export function LoginPage({ error }: Props) {
  
  const customAudience = process.env.NEXT_PUBLIC_CUSTOM_AUDIENCE || 'Your helpful';
  const productTitle = `${customAudience} AI assistant`;

  return (
    <div className="login-shell" data-carbon-theme="g100">
      <header className="login-header" role="banner">
        <span className="login-header__name">
          <span className="sub">{productTitle}</span>
        </span>
      </header>
      <main className="login-main">
        <div className="login-stack">
          <div className="login-eyebrow">Sign in</div>
          <h1 className="login-title">{productTitle}</h1>
          <p className="login-sub">
            Your AI. Your data. Sign in to start a governed conversation with your AI agent. No discount®. 
          </p>
          <a className="login-btn" href="/api/auth/login">
            <span>Login with Keycloak</span>
            <span className="login-btn__icon" aria-hidden="true">
              <svg viewBox="0 0 16 16" width="16" height="16" fill="none">
                <path
                  d="M3 8h10m-4-4 4 4-4 4"
                  stroke="currentColor"
                  strokeWidth="1.25"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </span>
          </a>
          {error ? (
            <div className="login-error" role="alert">
              {error}
            </div>
          ) : null}
          <div className="login-caption">
            Secured with Keycloak, LiteLLM &amp; Vault.
          </div>
        </div>
      </main>
    </div>
  );
}
