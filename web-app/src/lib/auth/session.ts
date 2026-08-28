import 'server-only';
import { cookies } from 'next/headers';
import { getIronSession, type IronSession } from 'iron-session';
import {
  COOKIE_NAMES,
  idTokenHintCookieOptions,
  pkceCookieOptions,
  sessionCookieOptions,
  stateCookieOptions,
  tokensCookieOptions,
} from '@/lib/auth/cookies';
import type { UserInfo } from '@/lib/auth/oauth';
import { decodeUnverified } from '@/lib/auth/jwt';

interface SessionMetaCookie {
  expires_at?: number;
  user_info?: UserInfo;
  preferred_username?: string;
}

interface TokensCookie {
  access_token?: string;
}

interface IdTokenHintCookie {
  id_token?: string;
}

export interface SessionData extends SessionMetaCookie, TokensCookie {}
export interface SessionWriteData extends SessionData {
  id_token?: string;
}

interface StateCookieData {
  state?: string;
}

interface PkceCookieData {
  verifier?: string;
}

async function readMetaCookie(): Promise<IronSession<SessionMetaCookie>> {
  return getIronSession<SessionMetaCookie>(await cookies(), sessionCookieOptions);
}

async function readTokensCookie(): Promise<IronSession<TokensCookie>> {
  return getIronSession<TokensCookie>(await cookies(), tokensCookieOptions);
}

async function readIdTokenHintCookie(): Promise<IronSession<IdTokenHintCookie>> {
  return getIronSession<IdTokenHintCookie>(await cookies(), idTokenHintCookieOptions);
}

export async function getSession(): Promise<SessionData | null> {
  const meta = await readMetaCookie();
  const tokens = await readTokensCookie();
  if (!tokens.access_token) return null;
  if (meta.expires_at && Date.now() / 1000 >= meta.expires_at) return null;
  return {
    access_token: tokens.access_token,
    expires_at: meta.expires_at,
    user_info: meta.user_info,
    preferred_username: meta.preferred_username,
  };
}

export async function requireAuth(): Promise<SessionData> {
  const s = await getSession();
  if (!s) {
    throw new Response('Unauthorized', { status: 401 });
  }
  return s;
}

export async function setSession(data: SessionWriteData): Promise<void> {
  const meta = await readMetaCookie();
  meta.expires_at = data.expires_at;
  meta.user_info = data.user_info;
  meta.preferred_username = data.preferred_username;
  await meta.save();

  const tokens = await readTokensCookie();
  tokens.access_token = data.access_token;
  await tokens.save();

  const idTokenHint = await readIdTokenHintCookie();
  idTokenHint.id_token = data.id_token;
  await idTokenHint.save();
}

export async function clearSession(): Promise<void> {
  const meta = await readMetaCookie();
  meta.destroy();
  const tokens = await readTokensCookie();
  tokens.destroy();
  const idTokenHint = await readIdTokenHintCookie();
  idTokenHint.destroy();
}

export async function getIdTokenHint(): Promise<string | undefined> {
  const idTokenHint = await readIdTokenHintCookie();
  return idTokenHint.id_token;
}

export async function setStateCookie(state: string): Promise<void> {
  const s = await getIronSession<StateCookieData>(await cookies(), stateCookieOptions);
  s.state = state;
  await s.save();
}

export async function readStateCookie(): Promise<string | undefined> {
  const s = await getIronSession<StateCookieData>(await cookies(), stateCookieOptions);
  return s.state;
}

export async function clearStateCookie(): Promise<void> {
  const s = await getIronSession<StateCookieData>(await cookies(), stateCookieOptions);
  s.destroy();
}

export async function setPkceCookie(verifier: string): Promise<void> {
  const s = await getIronSession<PkceCookieData>(await cookies(), pkceCookieOptions);
  s.verifier = verifier;
  await s.save();
}

export async function readPkceCookie(): Promise<string | undefined> {
  const s = await getIronSession<PkceCookieData>(await cookies(), pkceCookieOptions);
  return s.verifier;
}

export async function clearPkceCookie(): Promise<void> {
  const s = await getIronSession<PkceCookieData>(await cookies(), pkceCookieOptions);
  s.destroy();
}

export async function getDecodedAccessToken(): Promise<Record<string, unknown> | null> {
  const s = await getSession();
  if (!s?.access_token) return null;
  return decodeUnverified(s.access_token);
}

export function getThemeCookie(value: string | undefined): 'white' | 'g100' {
  return value === 'g100' ? 'g100' : 'white';
}

export const THEME_COOKIE = COOKIE_NAMES.theme;
