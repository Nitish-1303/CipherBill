type LogoProps = {
  size?: number;
  className?: string;
  title?: string;
};

/** Hand-drawn CipherBill mark: invoice slab + partial disclosure arc. */
export function CipherBillLogo({ size = 32, className, title = "CipherBill" }: LogoProps) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label={title}
    >
      <title>{title}</title>
      <rect x="1.5" y="1.5" width="29" height="29" rx="8" stroke="currentColor" strokeWidth="1.5" opacity="0.45" />
      <path
        d="M9 8h11.5a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2V10a2 2 0 0 1 2-2Z"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <path d="M11 13h8M11 16.5h6.5M11 20h4.5" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round" />
      <path
        d="M21.5 9.5a6.25 6.25 0 1 1-4.2 10.9"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <circle cx="22.75" cy="9.25" r="1.1" fill="currentColor" />
    </svg>
  );
}

export function CipherBillWordmark({ className }: { className?: string }) {
  return (
    <span className={className}>
      Cipher<span>Bill</span>
    </span>
  );
}
