import { NextResponse } from 'next/server';
import { clearSession } from '@/lib/auth/session';
import { withRequestContext } from '@/lib/log/with-request-context';
import { getLogger } from '@/lib/log/logger';

const log = getLogger('api.auth.logout');

export const dynamic = 'force-dynamic';

export const GET = withRequestContext(async () => {
  log.info('Logging out current session');
  await clearSession();
  return NextResponse.redirect(new URL('/', process.env.NEXTAUTH_URL ?? 'http://localhost:8080'), { status: 302 });
});
