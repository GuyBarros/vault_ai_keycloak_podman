'use client';

import { type KeyboardEvent, type Ref } from 'react';
import { CloseIcon, SendIcon } from '@/components/icons';

interface Props {
  value: string;
  onChange: (v: string) => void;
  onSend: () => void;
  onClear: () => void;
  disabled: boolean;
  textareaRef?: Ref<HTMLTextAreaElement>;
}

const MAX = 1000;

export function Composer({ value, onChange, onSend, onClear, disabled, textareaRef }: Props) {
  const canSend = value.trim().length > 0 && !disabled;

  function handleKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (canSend) onSend();
    }
  }

  return (
    <section className="composer" aria-label="Message composer">
      <label className="composer__label" htmlFor="msg">
        Message your AI agent
      </label>
      <textarea
        id="msg"
        ref={textareaRef}
        className="composer__textarea"
        placeholder="Type a message…"
        value={value}
        onChange={(e) => onChange(e.target.value.slice(0, MAX))}
        onKeyDown={handleKeyDown}
        rows={3}
      />
      <div className="composer__helper-row">
        <span>Press Enter to send, Shift+Enter for a new line.</span>
        <span>
          {value.length}/{MAX}
        </span>
      </div>
      <div className="composer__actions">
        <button
          type="button"
          className="composer__clear"
          onClick={onClear}
          title="Clear conversation (Ctrl+L)"
          aria-keyshortcuts="Control+L"
        >
          <span>Clear conversation</span>
          <kbd className="composer__shortcut">Ctrl+L</kbd>
          <span className="composer__icon">
            <CloseIcon size={16} />
          </span>
        </button>
        <button
          type="button"
          className="composer__send"
          onClick={onSend}
          disabled={!canSend}
        >
          <span>Send</span>
          <span className="composer__icon">
            <SendIcon size={16} />
          </span>
        </button>
      </div>
    </section>
  );
}
