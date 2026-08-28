import { NextResponse } from 'next/server';
import { getSession } from '@/lib/auth/session';
import { withRequestContext } from '@/lib/log/with-request-context';

export const dynamic = 'force-dynamic';

export const GET = withRequestContext(async () => {
  const s = await getSession();
  if (!s?.user_info) {
    return NextResponse.json({ error: 'unauthenticated' }, { status: 401 });
  }
  return NextResponse.json(
    {
      ...s.user_info,
      preferred_username: s.preferred_username ?? '',
    },
    { status: 200 },
  );
});
