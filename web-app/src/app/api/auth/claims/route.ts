import { NextResponse } from 'next/server';
import { getSession } from '@/lib/auth/session';
import { decodeUnverified } from '@/lib/auth/jwt';
import { withRequestContext } from '@/lib/log/with-request-context';

export const dynamic = 'force-dynamic';

export const GET = withRequestContext(async () => {
  const s = await getSession();
  if (!s?.access_token) {
    return NextResponse.json({ error: 'unauthenticated' }, { status: 401 });
  }
  const claims = decodeUnverified(s.access_token);
  return NextResponse.json({ token: s.access_token, claims }, { status: 200 });
});
