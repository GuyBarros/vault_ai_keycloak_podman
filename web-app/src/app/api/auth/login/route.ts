import { NextResponse } from 'next/server';
import { buildAuthorizeUrl } from '@/lib/auth/oauth';
import { challengeFromVerifier, generateState, generateVerifier } from '@/lib/auth/pkce';
import { setPkceCookie, setStateCookie } from '@/lib/auth/session';
import { withRequestContext } from '@/lib/log/with-request-context';
import { getLogger } from '@/lib/log/logger';

const log = getLogger('api.auth.login');

export const dynamic = 'force-dynamic';

export const GET = withRequestContext(async () => {
  const state = generateState();
  const verifier = generateVerifier();
  const challenge = challengeFromVerifier(verifier);

  await setStateCookie(state);
  await setPkceCookie(verifier);

  const url = buildAuthorizeUrl({ state, codeChallenge: challenge });
  log.warn('Redirecting to IdP authorize endpoint');
  return NextResponse.redirect(url, { status: 302 });
});
