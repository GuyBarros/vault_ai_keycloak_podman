import { getRequestId, REQUEST_ID_HEADER_NAME } from '@/lib/log/context';

export function buildOutboundHeaders(headers: Record<string, string> = {}): Record<string, string> {
  return { ...headers, [REQUEST_ID_HEADER_NAME]: getRequestId() };
}
