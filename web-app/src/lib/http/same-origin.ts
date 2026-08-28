export function isSameOrigin(req: Request): boolean {
  const url = new URL(req.url);
  const origin = req.headers.get('origin');
  if (origin) return origin === url.origin;
  const referer = req.headers.get('referer');
  if (referer) {
    try {
      return new URL(referer).origin === url.origin;
    } catch {
      return false;
    }
  }
  return false;
}
