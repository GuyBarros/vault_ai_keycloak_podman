import {
  extractClientIp,
  extractIncomingRequestId,
  extractIncomingTraceparent,
  extractIncomingTracestate,
  runWithRequestContext,
  setPreferredUsername,
  type RequestContext,
} from '@/lib/log/context';
import { getLogger } from '@/lib/log/logger';
import { getSession } from '@/lib/auth/session';

const log = getLogger('request');

type Handler<C> = (req: Request, ctx: C) => Promise<Response> | Response;

export function withRequestContext<C>(handler: Handler<C>): Handler<C> {
  return async (req, ctx) => {
    const url = new URL(req.url);
    const baseCtx: RequestContext = {
      request_id: extractIncomingRequestId(req.headers),
      client_ip: extractClientIp(req.headers),
      request_path: url.pathname,
      preferred_username: '',
      traceparent: extractIncomingTraceparent(req.headers),
      tracestate: extractIncomingTracestate(req.headers),
    };

    return runWithRequestContext(baseCtx, async () => {
      try {
        const session = await getSession();
        if (session?.preferred_username) setPreferredUsername(session.preferred_username);
      } catch {
        // session may be unreadable on unauthenticated routes; ignore
      }

      try {
        const res = await handler(req, ctx);
        log.debug({ method: req.method, status: res.status }, 'request completed');
        return res;
      } catch (err) {
        log.error({ err: String(err) }, 'request handler threw');
        throw err;
      }
    });
  };
}
