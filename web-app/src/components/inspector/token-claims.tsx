'use client';

import { Fragment, useState } from 'react';
import { formatClaimValue } from '@/lib/jwt-decode';
import { CheckIcon, CopyIcon } from '@/components/icons';

const PRIORITY = ['iss', 'sub', 'aud', 'amr', 'iat', 'exp', 'scope', 'client', 'act'] as const;

interface Props {
  claims: Record<string, unknown> | null;
  rawToken?: string;
  showRawToken?: boolean;
}

export function TokenClaims({ claims, rawToken, showRawToken }: Props) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    if (!rawToken) return;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(rawToken);
      } else {
        const ta = document.createElement('textarea');
        ta.value = rawToken;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // ignore copy failures silently
    }
  }

  if (!claims) {
    return <p className="inspector__placeholder">Send a message to populate this token.</p>;
  }
  const keys = Object.keys(claims);
  const ordered = [
    ...PRIORITY.filter((k) => keys.includes(k)),
    ...keys.filter((k) => !PRIORITY.includes(k as (typeof PRIORITY)[number])),
  ];

  return (
    <>
      <dl className="inspector__claims">
        {ordered.map((k) => (
          <Fragment key={k}>
            <dt>{k}</dt>
            <dd>{formatClaimValue(claims[k])}</dd>
          </Fragment>
        ))}
      </dl>
      {showRawToken && rawToken ? (
        <div className="inspector__token-wrap">
          <div className="inspector__token-header">
            <span className="inspector__token-label">Encoded JWT</span>
            <button
              type="button"
              className="inspector__copy"
              onClick={handleCopy}
              aria-label={copied ? 'Copied to clipboard' : 'Copy encoded JWT to clipboard'}
            >
              <span className="inspector__copy-icon">
                {copied ? <CheckIcon size={14} /> : <CopyIcon size={14} />}
              </span>
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <pre className="inspector__token-block">{rawToken}</pre>
        </div>
      ) : null}
    </>
  );
}
