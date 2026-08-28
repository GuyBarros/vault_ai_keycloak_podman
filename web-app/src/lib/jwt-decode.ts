function base64UrlToBase64(input: string): string {
  const padded = input + '='.repeat((4 - (input.length % 4)) % 4);
  return padded.replace(/-/g, '+').replace(/_/g, '/');
}

export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const json = atob(base64UrlToBase64(parts[1]!));
    const parsed = JSON.parse(json);
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export function formatClaimValue(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'number') {
    if (value > 1_000_000_000 && value < 10_000_000_000) {
      try {
        return new Date(value * 1000).toISOString();
      } catch {
        return String(value);
      }
    }
    return String(value);
  }
  if (Array.isArray(value)) return value.map((v) => String(v)).join(', ');
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
