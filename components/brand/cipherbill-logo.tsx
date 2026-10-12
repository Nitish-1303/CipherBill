type LogoProps = {
  size?: number;
  className?: string;
  title?: string;
};

/** Closed circuit: a private payment loop and protected core. */
export function CipherBillLogo({ size = 32, className, title = "CipherBill" }: LogoProps) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label={title}
    >
      <title>{title}</title>
      <path d="M50 9H25C13 9 5 18 5 32s8 23 20 23h25V43H26c-6 0-9-4-9-11s3-11 9-11h24V9Z" fill="currentColor" />
      <path d="M34 25h25v14H34V25ZM39 30v4h15v-4H39Z" fill="currentColor" fillRule="evenodd" />
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
