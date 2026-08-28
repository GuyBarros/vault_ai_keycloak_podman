interface Props {
  size?: number;
  color?: string;
  accent?: string;
  className?: string;
}

export function AiAgentLogo({
  size = 32,
  color = 'currentColor',
  accent = '#0f62fe',
  className,
}: Props) {
  return (
    <svg
      viewBox="0 0 32 32"
      width={size}
      height={size}
      role="img"
      aria-label="AI Agent"
      className={className}
    >
      <path
        d="M16 2 4 7v7.5c0 6.6 5.1 12.1 12 13 6.9-.9 12-6.4 12-13V7L16 2z"
        fill="none"
        stroke={color}
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <circle cx="16" cy="13" r="2.4" fill={accent} />
      <circle cx="10" cy="19" r="1.6" fill={color} />
      <circle cx="22" cy="19" r="1.6" fill={color} />
      <path
        d="M16 15.4 10 19m6-3.6 6 3.6M10 19v1.5m12-1.5v1.5"
        stroke={color}
        strokeWidth="1.2"
        strokeLinecap="round"
      />
    </svg>
  );
}
