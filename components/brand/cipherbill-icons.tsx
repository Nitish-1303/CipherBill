type IconProps = {
  size?: number;
  className?: string;
};

const base = {
  width: 24,
  height: 24,
  viewBox: "0 0 24 24",
  fill: "none",
  xmlns: "http://www.w3.org/2000/svg",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

export function IconShield({ size = 24, className }: IconProps) {
  return (
    <svg {...base} width={size} height={size} className={className} aria-hidden="true">
      <path d="M12 3.5 5 6.5v5.8c0 4.1 2.8 7.9 7 8.7 4.2-.8 7-4.6 7-8.7V6.5L12 3.5Z" />
      <path d="M8.5 12.2 11 14.7l4.8-4.8" />
    </svg>
  );
}

export function IconSettle({ size = 24, className }: IconProps) {
  return (
    <svg {...base} width={size} height={size} className={className} aria-hidden="true">
      <circle cx="6.5" cy="12" r="2.6" />
      <circle cx="17.5" cy="12" r="2.6" />
      <path d="M9.4 12h3.4m1.8 0H15" />
      <path d="M12 8.5v7" opacity="0.35" />
    </svg>
  );
}

export function IconProve({ size = 24, className }: IconProps) {
  return (
    <svg {...base} width={size} height={size} className={className} aria-hidden="true">
      <rect x="5" y="4" width="11" height="14" rx="1.5" />
      <path d="M8 8.5h5M8 11.5h3.5M8 14.5h4" />
      <path d="M15.5 9.5a4.2 4.2 0 1 1-2.8 3.9" />
      <circle cx="16.4" cy="9.2" r="0.85" fill="currentColor" stroke="none" />
    </svg>
  );
}

export function IconPool({ size = 24, className }: IconProps) {
  return (
    <svg {...base} width={size} height={size} className={className} aria-hidden="true">
      <ellipse cx="12" cy="7.5" rx="7.5" ry="2.6" />
      <path d="M4.5 7.5v3.8c0 1.4 3.4 2.6 7.5 2.6s7.5-1.2 7.5-2.6V7.5" />
      <path d="M4.5 11.3v3.8c0 1.4 3.4 2.6 7.5 2.6s7.5-1.2 7.5-2.6v-3.8" opacity="0.55" />
    </svg>
  );
}

export function IconConsole({ size = 24, className }: IconProps) {
  return (
    <svg {...base} width={size} height={size} className={className} aria-hidden="true">
      <rect x="3.5" y="4.5" width="17" height="12" rx="2" />
      <path d="M7 16.5h10M9.5 19h5" />
      <path d="M7.5 8.5h9M7.5 11.5h6" />
    </svg>
  );
}

export function IconBoundary({ size = 24, className }: IconProps) {
  return (
    <svg {...base} width={size} height={size} className={className} aria-hidden="true">
      <path d="M5 6.5h7v11H5z" />
      <path d="M12 6.5h7v11h-7z" opacity="0.45" />
      <path d="M7.5 9.5h2M7.5 12h3.5M7.5 14.5h2.5" />
      <path d="M14.5 9.5h2M14.5 12h3M14.5 14.5h2" />
    </svg>
  );
}

export function IconArrowDown({ size = 24, className }: IconProps) {
  return (
    <svg {...base} width={size} height={size} className={className} aria-hidden="true">
      <path d="M12 5v10" />
      <path d="m8.5 12.5 3.5 3.5 3.5-3.5" />
    </svg>
  );
}
