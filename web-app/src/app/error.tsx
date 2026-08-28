'use client';

import Link from 'next/link';
import { useEffect } from 'react';

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'grid',
        placeItems: 'center',
        background: 'var(--cds-background)',
        color: 'var(--cds-text-primary)',
        fontFamily: 'var(--cds-font-sans)',
        padding: 32,
      }}
    >
      <div style={{ maxWidth: 520, display: 'flex', flexDirection: 'column', gap: 16 }}>
        <h1 style={{ fontSize: 24, margin: 0, fontWeight: 400 }}>Something went wrong</h1>
        <p style={{ margin: 0, color: 'var(--cds-text-secondary)' }}>
          The application encountered an unexpected error. You can try again or return to the login
          page.
        </p>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={reset}
            style={{
              padding: '12px 32px',
              background: 'var(--cds-button-primary)',
              color: '#ffffff',
              border: 0,
              cursor: 'pointer',
            }}
          >
            Try again
          </button>
          <Link
            href="/"
            style={{
              padding: '12px 32px',
              background: 'transparent',
              color: 'var(--cds-link-primary)',
              border: '1px solid var(--cds-link-primary)',
              textDecoration: 'none',
            }}
          >
            Back to login
          </Link>
        </div>
      </div>
    </div>
  );
}
