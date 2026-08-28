export type ChatRole = 'user' | 'assistant';

export interface ChatMessage {
  role: ChatRole;
  content: string;
}

export interface AgentTokens {
  actor_token: string;
  // null when no OBO has been exchanged yet (e.g. no tool call has fired
  // since the last cache eviction) or when the broker isn't reachable.
  obo_token: string | null;
}

export interface AgentReply {
  response: string;
  obo_token?: string;
}
