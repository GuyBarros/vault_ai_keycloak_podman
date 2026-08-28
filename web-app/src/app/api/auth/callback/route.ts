import { NextResponse } from 'next/server';
import { exchangeCode, extractUserInfo } from '@/lib/auth/oauth';
import { verifyIdToken, decodeUnverified } from '@/lib/auth/jwt';
import {
  clearPkceCookie,
  clearStateCookie,
  readPkceCookie,
  readStateCookie,
  setSession,
} from '@/lib/auth/session';
import { timingSafeEqualString } from '@/lib/auth/pkce';
import { withRequestContext } from '@/lib/log/with-request-context';
import { setPreferredUsername } from '@/lib/log/context';
import { getLogger } from '@/lib/log/logger';

const log = getLogger('api.auth.callback');

export const dynamic = 'force-dynamic';

function browserOrigin(req: Request, fallback: string): string {
  const host = req.headers.get('host');
  if (!host) return fallback;
  const proto =
    req.headers.get('x-forwarded-proto')?.split(',')[0]?.trim() ||
    new URL(fallback).protocol.replace(':', '') ||
    'http';
  return `${proto}://${host}`;
}

export const GET = withRequestContext(async (req) => {
  const url = new URL(req.url);
  const origin = browserOrigin(req, url.origin);
  const code = url.searchParams.get('code');
  const stateParam = url.searchParams.get('state');
  const errorParam = url.searchParams.get('error');
  const errorDescription = url.searchParams.get('error_description');
  const errorCodes = url.searchParams.get('error_codes');
  const traceId = url.searchParams.get('trace_id');
  const correlationId = url.searchParams.get('correlation_id');

  if (errorParam) {
    log.warn(
      {
        error: errorParam,
        error_description: errorDescription ?? undefined,
        error_codes: errorCodes ?? undefined,
        trace_id: traceId ?? undefined,
        correlation_id: correlationId ?? undefined,
      },
      'OAuth provider returned an error',
    );

    const redirect = new URL('/?error=' + encodeURIComponent(errorParam), origin);
    if (errorDescription) {
      redirect.searchParams.set('error_description', errorDescription);
    }
    if (traceId) {
      redirect.searchParams.set('trace_id', traceId);
    }

    return NextResponse.redirect(redirect);
  }

  if (!code || !stateParam) {
    log.warn('Missing code or state in callback');
    return new NextResponse('Missing code or state', { status: 400 });
  }

  const expectedState = await readStateCookie();
  const verifier = await readPkceCookie();

  if (!expectedState || !verifier || !timingSafeEqualString(stateParam, expectedState)) {
    log.warn('State or PKCE verifier missing/mismatch');
    await clearStateCookie();
    await clearPkceCookie();
    return new NextResponse('Invalid OAuth state', { status: 400 });
  }

  try {
    const tokens = await exchangeCode(code, verifier);
    const claims = await verifyIdToken(tokens.id_token);
    const userInfo = extractUserInfo(claims);
    const accessClaims = decodeUnverified(tokens.access_token);
    const preferredUsername =
      (typeof accessClaims.preferred_username === 'string' && accessClaims.preferred_username) ||
      (typeof claims.preferred_username === 'string' && claims.preferred_username) ||
      '';

    if (preferredUsername) setPreferredUsername(preferredUsername);

    const expiresAt = Math.floor(Date.now() / 1000) + (tokens.expires_in ?? 3600);

    await setSession({
      access_token: tokens.access_token,
      id_token: tokens.id_token,
      expires_at: expiresAt,
      user_info: userInfo,
      preferred_username: preferredUsername,
    });

    await clearStateCookie();
    await clearPkceCookie();

    log.warn('Authentication completed successfully');
    return NextResponse.redirect(new URL('/landing', origin), { status: 302 });
  } catch (err) {
    log.error({ err: String(err) }, 'OAuth callback failed');
    await clearStateCookie();
    await clearPkceCookie();
    return new NextResponse('Authentication failed', { status: 500 });
  }
});
