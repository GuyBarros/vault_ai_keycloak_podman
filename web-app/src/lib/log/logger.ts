import { hostname } from 'node:os';
import { lookup } from 'node:dns/promises';
import pino, { type LoggerOptions } from 'pino';
import { config } from '@/lib/config';
import { getRequestContext } from '@/lib/log/context';

const HOSTNAME = hostname();

let HOST_IP = '127.0.0.1';
lookup(HOSTNAME, { family: 4 })
  .then((res) => {
    if (res.address && !res.address.startsWith('127.')) HOST_IP = res.address;
  })
  .catch(() => {
    // best-effort; keep default
  });

const SENSITIVE_KEYS = new Set([
  'access_token',
  'id_token',
  'refresh_token',
  'client_secret',
  'code',
  'code_verifier',
  'authorization',
  'session_password',
  'set-cookie',
  'cookie',
]);

function redact<T>(value: T): T {
  if (!value || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(redact) as unknown as T;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (SENSITIVE_KEYS.has(k.toLowerCase())) {
      out[k] = '<redacted>';
    } else {
      out[k] = redact(v);
    }
  }
  return out as unknown as T;
}

const baseOptions: LoggerOptions = {
  level: config.LOG_LEVEL,
  base: undefined,
  messageKey: 'message',
  timestamp: () => `,"timestamp":"${new Date().toISOString()}"`,
  formatters: {
    level(label) {
      return { level: label.toUpperCase(), severity: label.toUpperCase() };
    },
    log(obj) {
      const ctx = getRequestContext();
      return {
        service: config.LOG_SERVICE_NAME,
        environment: config.LOG_ENVIRONMENT,
        host: HOSTNAME,
        hostname: HOSTNAME,
        host_ip: HOST_IP,
        request_id: ctx.request_id,
        client_ip: ctx.client_ip,
        request_path: ctx.request_path,
        user: ctx.preferred_username || undefined,
        process: process.pid,
        process_name: process.title,
        thread: 0,
        thread_name: 'main',
        ...redact(obj),
      };
    },
  },
  hooks: {
    logMethod(inputArgs, method) {
      const ctx = getRequestContext();
      if (ctx.preferred_username) {
        const prefix = `[user=${ctx.preferred_username}] `;
        if (typeof inputArgs[0] === 'string') {
          inputArgs[0] = prefix + inputArgs[0];
        } else if (inputArgs.length >= 2 && typeof inputArgs[1] === 'string') {
          inputArgs[1] = prefix + inputArgs[1];
        }
      }
      return method.apply(this, inputArgs as Parameters<typeof method>);
    },
  },
};

const root = pino(baseOptions);

export function getLogger(name: string) {
  return root.child({ logger: `verify_vault.${name}`, module: name });
}
