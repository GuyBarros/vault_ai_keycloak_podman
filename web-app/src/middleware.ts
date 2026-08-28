import { NextResponse, type NextRequest } from 'next/server';
import { COOKIE_NAMES } from '@/lib/auth/cookies';

const PROTECTED_PAGE_PATHS = ['/landing'];
const PROTECTED_API_PATHS = ['/api/agent', '/api/auth/claims', '/api/auth/me'];

function isProtectedPage(pathname: string): boolean {
  return PROTECTED_PAGE_PATHS.some((p) => pathname === p || pathname.startsWith(p + '/'));
}

function isProtectedApi(pathname: string): boolean {
  return PROTECTED_API_PATHS.some((p) => pathname === p || pathname.startsWith(p + '/'));
}

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  const hasSession = req.cookies.has(COOKIE_NAMES.session);

  if (isProtectedApi(pathname) && !hasSession) {
    return NextResponse.json({ error: 'unauthenticated' }, { status: 401 });
  }

  if (isProtectedPage(pathname) && !hasSession) {
    const url = req.nextUrl.clone();
    url.pathname = '/';
    url.search = '';
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/landing/:path*', '/api/agent/:path*', '/api/auth/claims', '/api/auth/me'],
};
