import type { SessionOptions } from 'iron-session';
import { config } from '@/lib/config';

// COOKIE_SECURE can be set to "false" to disable the Secure flag when running
// behind plain HTTP (e.g. local Docker without TLS termination).
const secureCookies = process.env.COOKIE_SECURE !== 'false';

const baseCookie = {
  httpOnly: true,
  secure: secureCookies,
  sameSite: 'lax',
  path: '/',
} as const;

export const COOKIE_NAMES = {
  session: 'verify_session',
  tokens: 'verify_tokens',
  idTokenHint: 'verify_id_token_hint',
  state: 'verify_oauth_state',
  pkce: 'verify_pkce_verifier',
  theme: 'verify_theme',
} as const;

export const sessionCookieOptions: SessionOptions = {
  password: config.SESSION_PASSWORD,
  cookieName: COOKIE_NAMES.session,
  cookieOptions: {
    ...baseCookie,
    path: '/',
    maxAge: 60 * 60 * 8,
  },
};

export const tokensCookieOptions: SessionOptions = {
  password: config.SESSION_PASSWORD,
  cookieName: COOKIE_NAMES.tokens,
  cookieOptions: {
    ...baseCookie,
    path: '/',
    maxAge: 60 * 60 * 8,
  },
};

export const idTokenHintCookieOptions: SessionOptions = {
  password: config.SESSION_PASSWORD,
  cookieName: COOKIE_NAMES.idTokenHint,
  cookieOptions: {
    ...baseCookie,
    path: '/',
    maxAge: 60 * 60 * 8,
  },
};

export const stateCookieOptions: SessionOptions = {
  password: config.SESSION_PASSWORD,
  cookieName: COOKIE_NAMES.state,
  cookieOptions: {
    ...baseCookie,
    path: '/',
    maxAge: 60 * 10,
  },
};

export const pkceCookieOptions: SessionOptions = {
  password: config.SESSION_PASSWORD,
  cookieName: COOKIE_NAMES.pkce,
  cookieOptions: {
    ...baseCookie,
    path: '/',
    maxAge: 60 * 10,
  },
};
