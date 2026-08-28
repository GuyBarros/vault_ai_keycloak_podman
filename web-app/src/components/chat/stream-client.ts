import type { ChatMessage } from '@/types/agent';

export class AgentRequestError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = 'AgentRequestError';
  }
}

export interface StreamCallbacks {
  onChunk: (chunk: string) => void;
  onDone: () => void;
  onError: (err: Error) => void;
}

export async function streamAgent(
  message: string,
  history: ChatMessage[],
  signal: AbortSignal,
  cb: StreamCallbacks,
): Promise<void> {
  let res: Response;
  try {
    res = await fetch('/api/agent/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, history }),
      signal,
    });
  } catch (err) {
    cb.onError(err instanceof Error ? err : new Error(String(err)));
    return;
  }

  if (!res.ok) {
    let detail = '';
    try {
      const data = await res.json();
      detail = typeof data.detail === 'string' ? data.detail : JSON.stringify(data);
    } catch {
      detail = await res.text().catch(() => '');
    }
    detail = detail.trim().replace(/^"|"$/g, '');
    cb.onError(new AgentRequestError(detail || `Agent request failed (${res.status})`, res.status));
    return;
  }

  if (!res.body) {
    cb.onDone();
    return;
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder('utf-8');

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.length) cb.onChunk(decoder.decode(value, { stream: true }));
    }
    const tail = decoder.decode();
    if (tail) cb.onChunk(tail);
    cb.onDone();
  } catch (err) {
    cb.onError(err instanceof Error ? err : new Error(String(err)));
  }
}
