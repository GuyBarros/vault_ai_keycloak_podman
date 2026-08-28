export default function Loading() {
  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'grid',
        placeItems: 'center',
        background: 'var(--cds-background)',
        color: 'var(--cds-text-secondary)',
        fontFamily: 'var(--cds-font-sans)',
        fontSize: 14,
      }}
    >
      Loading…
    </div>
  );
}
