import { NextResponse } from 'next/server';
import { jwtVerify } from 'jose';
import { config } from '@/lib/config';
import { getJwks } from '@/lib/auth/jwks';
import { revokeSid, revokeSubject } from '@/lib/auth/revoked-sessions';
import { getLogger } from '@/lib/log/logger';

const log = getLogger('api.auth.backchannel-logout');
const BACKCHANNEL_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

export const dynamic = 'force-dynamic';

export async function POST(req: Request) {
  const contentType = req.headers.get('content-type') || '';
  let logoutToken = '';
  if (contentType.includes('application/x-www-form-urlencoded')) {
    const form = await req.formData();
    logoutToken = String(form.get('logout_token') || '');
  } else {
    logoutToken = (await req.text()).trim();
  }
  if (!logoutToken) {
    return NextResponse.json({ error: 'missing_logout_token' }, { status: 400 });
  }
  try {
    const { payload } = await jwtVerify(logoutToken, getJwks(), {
      issuer: `${config.KEYCLOAK_BASE_URL}/realms/${config.KEYCLOAK_REALM}`,
      audience: config.KEYCLOAK_CLIENT_ID,
      algorithms: ['RS256'],
      clockTolerance: 30,
    });
    const events = payload.events;
    if (
      events === null ||
      typeof events !== 'object' ||
      !(BACKCHANNEL_EVENT in events)
    ) {
      return NextResponse.json({ error: 'not_backchannel_logout' }, { status: 400 });
    }
    const sid = typeof payload.sid === 'string' ? payload.sid : undefined;
    const sub = typeof payload.sub === 'string' ? payload.sub : undefined;
    revokeSid(sid);
    revokeSubject(sub);
    log.warn({ sid: sid ? 'set' : undefined }, 'OIDC backchannel logout — session revoked at RP');
    return new NextResponse(null, { status: 204 });
  } catch (err) {
    log.warn({ err: String(err) }, 'backchannel logout token rejected');
    return NextResponse.json({ error: 'invalid_logout_token' }, { status: 400 });
  }
}
