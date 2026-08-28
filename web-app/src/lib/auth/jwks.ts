import { createRemoteJWKSet } from 'jose';
import { oidc } from '@/lib/config';

let cachedJwks: ReturnType<typeof createRemoteJWKSet> | null = null;

export function getJwks() {
  if (!cachedJwks) {
    cachedJwks = createRemoteJWKSet(new URL(oidc.jwksUrl));
  }
  return cachedJwks;
}
