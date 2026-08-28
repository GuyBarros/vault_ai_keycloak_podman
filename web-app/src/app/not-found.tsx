import Link from 'next/link';

export default function NotFound() {
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
        <h1 style={{ fontSize: 24, margin: 0, fontWeight: 400 }}>Page not found</h1>
        <p style={{ margin: 0, color: 'var(--cds-text-secondary)' }}>
          The page you requested does not exist.
        </p>
        <Link
          href="/"
          style={{
            padding: '12px 32px',
            background: 'var(--cds-button-primary)',
            color: '#ffffff',
            textDecoration: 'none',
            width: 'max-content',
          }}
        >
          Back to login
        </Link>
      </div>
    </div>
  );
}
