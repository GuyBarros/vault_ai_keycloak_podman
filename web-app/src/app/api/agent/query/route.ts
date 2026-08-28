import { NextResponse } from 'next/server';
import { z } from 'zod';
import { getSession } from '@/lib/auth/session';
import { AgentUpstreamError, invokeStream } from '@/lib/agent/client';
import { getRequestId, getTraceparent, getTracestate } from '@/lib/log/context';
import { withRequestContext } from '@/lib/log/with-request-context';
import { getLogger } from '@/lib/log/logger';

const log = getLogger('api.agent.query');

const bodySchema = z.object({
  message: z.string().min(1).max(1000),
  history: z
    .array(
      z.object({
        role: z.enum(['user', 'assistant']),
        content: z.string(),
      }),
    )
    .max(200)
    .default([]),
});

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';
export const maxDuration = 120;

// TODO: add rate limiting (e.g., upstash/ratelimit) before production deployment.

export const POST = withRequestContext(async (req) => {
  const session = await getSession();
  if (!session?.access_token) {
    return NextResponse.json({ error: 'unauthenticated' }, { status: 401 });
  }

  let parsed;
  try {
    parsed = bodySchema.safeParse(await req.json());
  } catch {
    return NextResponse.json({ error: 'invalid_json' }, { status: 400 });
  }
  if (!parsed.success) {
    return NextResponse.json({ error: 'invalid_body', issues: parsed.error.issues }, { status: 400 });
  }

  if (parsed.data.history.length === 0) {
    log.info('New chat conversation started');
  }
  log.debug({ historyLength: parsed.data.history.length }, 'Streaming agent response');

  try {
    const stream = await invokeStream({
      message: parsed.data.message,
      history: parsed.data.history,
      accessToken: session.access_token,
      traceparent: getTraceparent(),
      tracestate: getTracestate(),
    });

    return new Response(stream, {
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Request-ID': getRequestId(),
        'Traceparent': getTraceparent(),
        'Tracestate': getTracestate(),
      },
    });
  } catch (err) {
    if (err instanceof AgentUpstreamError) {
      return NextResponse.json(
        { error: 'agent_error', detail: err.body || 'Agent request was rejected.' },
        { status: err.status, headers: { 'X-Request-ID': getRequestId(), 'Traceparent': getTraceparent(), 'Tracestate': getTracestate() } },
      );
    }
    log.error({ err: String(err) }, 'Failed to start agent stream');
    return NextResponse.json({ error: 'agent_unavailable', detail: String(err) }, { status: 502 });
  }
});
