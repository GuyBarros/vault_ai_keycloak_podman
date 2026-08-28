interface IconProps {
  size?: number;
  className?: string;
}

export function ChevronRightIcon({ size = 16, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M6 4l4 4-4 4-.7-.7L8.6 8 5.3 4.7z" />
    </svg>
  );
}

export function ArrowRightIcon({ size = 16, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M11.3 8 7.1 3.8l.7-.7L12.7 8l-4.9 4.9-.7-.7z" />
      <path d="M3 7.5h9v1H3z" />
    </svg>
  );
}

export function SendIcon({ size = 16, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M14.5 1.5 1 6.5l5 2 2 5z" />
    </svg>
  );
}

export function CloseIcon({ size = 16, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M12 4.7 11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3l.7.7L8 8.7l3.3 3.3.7-.7L8.7 8z" />
    </svg>
  );
}

export function UserIcon({ size = 16, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M8 8a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm0-5a2 2 0 1 0 0 4 2 2 0 0 0 0-4z" />
      <path d="M14 14H2v-1.5C2 10.6 4.7 9 8 9s6 1.6 6 3.5z" />
    </svg>
  );
}

export function CopyIcon({ size = 16, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M10 1H4a1 1 0 0 0-1 1v1H2a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h1a1 1 0 0 0 1-1V5L10 1zm0 1.4L12.6 5H10V2.4zM10 14H2V4h1v8a1 1 0 0 0 1 1h6v1zm2-2H4V2h5v4h3v6z" />
    </svg>
  );
}

export function CheckIcon({ size = 16, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M6.4 11.2 2.8 7.6l1-1L6.4 9.2l5.8-5.8 1 1z" />
    </svg>
  );
}

export function WarningIcon({ size = 16, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M8 1 0.5 14h15L8 1zm0 2 5.8 10H2.2L8 3zm-0.5 3v4h1V6h-1zm0 5v1h1v-1h-1z" />
    </svg>
  );
}

export function ErrorIcon({ size = 16, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M8 1a7 7 0 1 0 0 14A7 7 0 0 0 8 1zm0 1a6 6 0 1 1 0 12A6 6 0 0 1 8 2zm-.5 3v4h1V5h-1zm0 5v1h1v-1h-1z" />
    </svg>
  );
}

export function AgentIcon({ size = 16, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M8 1 2 4v4c0 3.5 2.5 6.6 6 7 3.5-.4 6-3.5 6-7V4L8 1zm0 1.1L13 4.6V8c0 2.9-2 5.4-5 5.9-3-.5-5-3-5-5.9V4.6l5-2.5z" />
      <path d="M7 9.3 5.7 8l-.7.7L7 10.7l4-4-.7-.7z" />
    </svg>
  );
}
