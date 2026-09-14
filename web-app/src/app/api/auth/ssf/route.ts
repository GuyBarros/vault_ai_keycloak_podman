import { NextResponse } from 'next/server';
import { jwtVerify } from 'jose';
import { config } from '@/lib/config';
import { getJwks } from '@/lib/auth/jwks';
import { revokeSid, revokeSubject } from '@/lib/auth/revoked-sessions';
import { getLogger } from '@/lib/log/logger';

const log = getLogger('api.auth.ssf');
const CAEP_SESSION_REVOKED =
  'https://schemas.openid.net/secevent/caep/event-type/session-revoked';

export const dynamic = 'force-dynamic';

/**
 * RFC 8935 PUSH endpoint for Keycloak SSF / CAEP session-revoked SETs.
 * Same RP action as OIDC backchannel logout: drop the cached session.
 */
export async function POST(req: Request) {
  const raw = (await req.text()).trim();
  if (!raw) {
    return NextResponse.json({ error: 'empty' }, { status: 400 });
  }
  try {
    const { payload } = await jwtVerify(raw, getJwks(), {
      issuer: `${config.KEYCLOAK_BASE_URL}/realms/${config.KEYCLOAK_REALM}`,
      algorithms: ['RS256'],
      clockTolerance: 30,
    });
    const events = payload.events;
    if (
      events === null ||
      typeof events !== 'object' ||
      !(CAEP_SESSION_REVOKED in events)
    ) {
      return NextResponse.json({ error: 'ignored' }, { status: 204 });
    }
    const sid = typeof payload.sid === 'string' ? payload.sid : undefined;
    let sub = typeof payload.sub === 'string' ? payload.sub : undefined;
    const subId = (payload as { sub_id?: { format?: string; email?: string; sub?: string } }).sub_id;
    if (!sub && subId?.email) sub = subId.email;
    if (!sub && subId?.sub) sub = subId.sub;
    revokeSid(sid);
    revokeSubject(sub);
    log.warn({ sid: sid ? 'set' : undefined }, 'CAEP session-revoked SET — session dropped at RP');
    return new NextResponse(null, { status: 204 });
  } catch (err) {
    log.warn({ err: String(err) }, 'SSF SET rejected');
    return NextResponse.json({ error: 'invalid_set' }, { status: 400 });
  }
}
