/**
 * Sid / subject denylist filled by OIDC backchannel logout (and CAEP SETs).
 * In-memory is enough for this single-replica demo: Keycloak push + the next
 * getSession() drop the browser cookies.
 */
const sids = new Set<string>();
const subjects = new Set<string>();

export function revokeSid(sid: string | undefined | null): void {
  if (sid) sids.add(sid);
}

export function revokeSubject(sub: string | undefined | null): void {
  if (sub) subjects.add(sub);
}

export function isSidRevoked(sid: string | undefined | null): boolean {
  return Boolean(sid && sids.has(sid));
}

export function isSubjectRevoked(sub: string | undefined | null): boolean {
  return Boolean(sub && subjects.has(sub));
}
