interface LogoProps {
  /** "inverse": kırmızı zemin üzerinde beyaz logo. */
  variant?: "default" | "inverse";
  showText?: boolean;
}

export function Logo({ variant = "default", showText = true }: LogoProps) {
  return (
    <span className={`logo logo-${variant}`}>
      <svg className="logo-mark" viewBox="0 0 32 32" aria-hidden="true">
        <path
          className="logo-shield"
          d="M16 2.5 4.5 6.8v8.4c0 7 4.9 12.6 11.5 14.3 6.6-1.7 11.5-7.3 11.5-14.3V6.8L16 2.5Z"
        />
        <path
          className="logo-check"
          d="m10.5 16.2 3.8 3.8 7.4-8"
          fill="none"
          strokeWidth="2.6"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      {showText && (
        <span className="logo-text">
          <span className="logo-text-light">Ber</span>
          <strong>Ops</strong>
        </span>
      )}
    </span>
  );
}
