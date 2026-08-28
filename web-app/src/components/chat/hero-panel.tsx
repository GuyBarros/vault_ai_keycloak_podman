'use client';

import { ArrowRightIcon } from '@/components/icons';

interface Props {
  username: string;
  msgCount: number;
  onStart: () => void;
}

export function HeroPanel({ username, msgCount, onStart }: Props) {
  const firstName = username.split(/\s+/)[0] || username;
  return (
    <section className="hero" aria-label="Workspace overview">
      <div className="eyebrow">Workspace</div>
      <h1 className="hero__title">
        Secure conversations
        <br />
        for your AI runtime.
      </h1>
      <p className="hero__body">
        Welcome, {firstName}. Launch a governed conversation, inspect the delegated identity, and
        keep the agent workspace anchored in one focused control surface.
      </p>
      <button type="button" className="hero__cta" onClick={onStart}>
        <span>Start chatting</span>
        <span aria-hidden="true" style={{ display: 'inline-flex' }}>
          <ArrowRightIcon size={16} />
        </span>
      </button>

      <div className="hero__tile">
        <div className="eyebrow">Conversation</div>
        <div className="hero__tile-count">
          {msgCount} message{msgCount === 1 ? '' : 's'}
        </div>
        <p className="helper">History stays in-session for a continuous operator flow.</p>
      </div>
    </section>
  );
}
