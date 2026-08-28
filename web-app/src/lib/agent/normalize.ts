const ESCAPE_MARKERS = ['\\r\\n', '\\n', '\\r', '\\t', '\\"', '\\/'] as const;

export function decodeEscapedPlaintext(content: string): string {
  if (!ESCAPE_MARKERS.some((m) => content.includes(m))) return content;

  const stripped = content.trim();
  const looksWrapped =
    stripped.startsWith('"') &&
    (stripped.endsWith('"') || stripped.includes('\\n') || stripped.includes('\\"'));
  const looksEscapedMultiline = content.includes('\\n') && !content.includes('\n');
  const looksEscapedQuotes = content.includes('\\"') && !content.includes('"');
  if (!(looksWrapped || looksEscapedMultiline || looksEscapedQuotes)) return content;

  const prefixLength = content.length - content.trimStart().length;
  const suffixLength = content.length - content.trimEnd().length;
  const prefix = content.slice(0, prefixLength);
  const suffix = suffixLength ? content.slice(content.length - suffixLength) : '';
  let body = stripped;

  if (body.startsWith('"')) body = body.slice(1);
  if (body.endsWith('"') && !body.endsWith('\\"')) body = body.slice(0, -1);

  body = body
    .replaceAll('\\r\\n', '\n')
    .replaceAll('\\n', '\n')
    .replaceAll('\\r', '\r')
    .replaceAll('\\t', '\t')
    .replaceAll('\\"', '"')
    .replaceAll('\\/', '/');

  return `${prefix}${body}${suffix}`;
}

export function normalizeMessageContent(content: string): string {
  const stripped = content.trim();
  if (!stripped.startsWith('{')) return decodeEscapedPlaintext(content);

  let payload: unknown;
  try {
    payload = JSON.parse(stripped);
  } catch {
    return decodeEscapedPlaintext(content);
  }

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return decodeEscapedPlaintext(content);
  }

  const obj = payload as Record<string, unknown>;
  const candidate =
    (typeof obj.response_text === 'string' && obj.response_text) ||
    (typeof obj.response === 'string' && obj.response) ||
    (typeof obj.result === 'string' && obj.result) ||
    (typeof obj.message === 'string' && obj.message) ||
    content;

  return decodeEscapedPlaintext(String(candidate));
}

export function normalizeAgentTokensPayload(
  data: unknown,
): { actor_token: string; obo_token: string | null } | null {
  if (typeof data === 'string') {
    const stripped = data.trim();
    if (!stripped) return null;
    try {
      return normalizeAgentTokensPayload(JSON.parse(stripped));
    } catch {
      return null;
    }
  }

  if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
  const obj = data as Record<string, unknown>;
  const actor = obj.actor_token;
  const obo = obj.obo_token;
  if (actor !== undefined || obo !== undefined) {
    return {
      actor_token: actor == null ? '' : String(actor),
      // Preserve null/missing OBO so the UI can render "Not available"
      // instead of treating an empty string as a (zero-length) JWT.
      obo_token: obo == null ? null : String(obo),
    };
  }

  for (const key of ['data', 'result', 'response', 'payload', 'body'] as const) {
    if (key in obj) {
      const nested = normalizeAgentTokensPayload(obj[key]);
      if (nested) return nested;
    }
  }

  return null;
}
