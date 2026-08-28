import { config, oidc } from '@/lib/config';
import { buildOutboundHeaders } from '@/lib/log/outbound';
import { getLogger } from '@/lib/log/logger';

const log = getLogger('auth.oauth');

export interface AuthorizeUrlInput {
  state: string;
  codeChallenge: string;
}

export function buildAuthorizeUrl({ state, codeChallenge }: AuthorizeUrlInput): string {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.KEYCLOAK_CLIENT_ID,
    redirect_uri: config.KEYCLOAK_REDIRECT_URI,
    scope: config.KEYCLOAK_SCOPES,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    prompt: 'login',
  });
  return `${oidc.authorizeUrl}?${params.toString()}`;
}

export interface TokenResponse {
  access_token: string;
  id_token: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
  refresh_token?: string;
}

export async function exchangeCode(code: string, codeVerifier: string): Promise<TokenResponse> {
  log.debug('Exchanging authorization code for tokens');
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.KEYCLOAK_REDIRECT_URI,
    client_id: config.KEYCLOAK_CLIENT_ID,
    client_secret: config.KEYCLOAK_CLIENT_SECRET,
    code_verifier: codeVerifier,
  });

  const res = await fetch(oidc.tokenUrl, {
    method: 'POST',
    headers: buildOutboundHeaders({
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    }),
    body,
    signal: AbortSignal.timeout(15_000),
  });

  if (!res.ok) {
    const errBody = await res.text().catch(() => '');
    log.error({ status: res.status }, 'token exchange failed');
    throw new Error(`Token exchange failed: ${res.status} ${errBody}`);
  }

  const json = (await res.json()) as TokenResponse;
  log.debug({ status: res.status }, 'Token exchange completed');
  return json;
}

export function buildLogoutUrl(idToken: string): string {
  const params = new URLSearchParams({
    post_logout_redirect_uri: config.KEYCLOAK_LOGOUT_URI,
  });
  if (idToken) params.set('id_token_hint', idToken);
  return `${oidc.logoutUrl}?${params.toString()}`;
}

export interface UserInfo {
  name: string;
  email: string;
  initials: string;
  sub: string;
}

export function extractUserInfo(claims: Record<string, unknown>): UserInfo {
  const rawName =
    (typeof claims.name === 'string' && claims.name) ||
    (typeof claims.preferred_username === 'string' && claims.preferred_username) ||
    (typeof claims.sub === 'string' && claims.sub) ||
    'User';
  const email = typeof claims.email === 'string' ? claims.email : '';
  const sub = typeof claims.sub === 'string' ? claims.sub : '';
  const parts = String(rawName).split(/\s+/).filter(Boolean).slice(0, 2);
  const initials = parts.length
    ? parts.map((p) => p[0]!.toUpperCase()).join('')
    : '?';
  return { name: String(rawName), email, initials, sub };
}
