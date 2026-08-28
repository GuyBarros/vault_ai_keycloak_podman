'use client';

import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { AgentIcon, ErrorIcon, UserIcon, WarningIcon } from '@/components/icons';
import { TypingIndicator } from '@/components/chat/typing-indicator';

export type MessageRole = 'user' | 'agent';

interface Props {
  role: MessageRole;
  text: string;
  showTyping?: boolean;
  errorStatus?: number;
}

function errorVariant(status?: number): 'warning' | 'error' | null {
  if (!status) return null;
  if (status >= 400 && status < 500) return 'warning';
  if (status >= 500 && status < 600) return 'error';
  return null;
}

export function MessageBubble({ role, text, showTyping, errorStatus }: Props) {
  const variant = errorVariant(errorStatus);
  const label = role === 'user' ? 'You' : variant ? `Agent · ${errorStatus}` : 'Agent';
  const Icon =
    variant === 'error'
      ? ErrorIcon
      : variant === 'warning'
        ? WarningIcon
        : role === 'user'
          ? UserIcon
          : AgentIcon;
  const classes = ['msg', `msg--${role}`];
  if (variant) classes.push(`msg--${variant}`);
  return (
    <div className={classes.join(' ')} role={variant ? 'alert' : undefined}>
      <div className="msg__meta">
        <span className="msg__icon">
          <Icon size={16} />
        </span>
        <span className="msg__label">{label}</span>
      </div>
      <div className="msg__text">
        {showTyping ? (
          <TypingIndicator />
        ) : role === 'agent' && !variant ? (
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{text}</ReactMarkdown>
        ) : (
          text
        )}
      </div>
    </div>
  );
}
