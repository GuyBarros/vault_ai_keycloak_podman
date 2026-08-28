import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';

export interface RequestContext {
  request_id: string;
  client_ip: string;
  request_path: string;
  preferred_username: string;
  traceparent?: string;
  tracestate?: string;
}

const storage = new AsyncLocalStorage<RequestContext>();

export function runWithRequestContext<T>(ctx: RequestContext, fn: () => T): T {
  return storage.run(ctx, fn);
}

export function getRequestContext(): RequestContext {
  return (
    storage.getStore() ?? {
      request_id: '-',
      client_ip: '-',
      request_path: '-',
      preferred_username: '',
      traceparent: '',
      tracestate: '',
    }
  );
}

export function setPreferredUsername(name: string): void {
  const ctx = storage.getStore();
  if (ctx) ctx.preferred_username = name;
}

export function getRequestId(): string {
  const ctx = storage.getStore();
  if (ctx?.request_id && ctx.request_id !== '-') return ctx.request_id;
  return randomUUID();
}

export function getTraceparent(): string {
  const ctx = storage.getStore();
  if (ctx?.traceparent && ctx.traceparent !== '-') return ctx.traceparent;
  return '';
}

export function getTracestate(): string {
  const ctx = storage.getStore();
  if (ctx?.tracestate && ctx.tracestate !== '-') return ctx.tracestate;
  return '';
}

const CLIENT_IP_HEADERS = ['x-forwarded-for', 'x-real-ip', 'cf-connecting-ip'] as const;
const REQUEST_ID_HEADER = 'x-request-id';
const TRACEPARENT_HEADER = 'traceparent';
const TRACESTATE_HEADER = 'tracestate';

export function extractClientIp(headers: Headers): string {
  for (const name of CLIENT_IP_HEADERS) {
    const raw = headers.get(name);
    if (raw && raw.trim()) return raw.split(',')[0]!.trim();
  }
  return '-';
}

export function extractIncomingRequestId(headers: Headers): string {
  const raw = headers.get(REQUEST_ID_HEADER);
  return raw && raw.trim() ? raw.trim() : randomUUID();
}

export function extractIncomingTraceparent(headers: Headers): string {
  const raw = headers.get(TRACEPARENT_HEADER);
  return raw && raw.trim() ? raw.trim() : '';
}

// export function extractIncomingTracestate(headers: Headers): string {
//   const raw = headers.get(TRACESTATE_HEADER);
//   return raw && raw.trim() ? raw.trim() : '';
// }

export function extractIncomingTracestate(headers: Headers): string {
  const raw = headers.get(TRACESTATE_HEADER);
  if (!raw || !raw.trim()) return '';

  return raw
    .split(',')
    .map((member) => member.trim())
    .filter(Boolean)
    .map((member) => (member.includes('=') ? member : `instana=${member}`))
    .join(',');
}

export const REQUEST_ID_HEADER_NAME = 'X-Request-ID';
