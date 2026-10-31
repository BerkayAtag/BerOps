import { useTranslation } from "react-i18next";
import { riskLevel } from "../risk";

export function OnlinePill({ online }: { online: boolean }) {
  const { t } = useTranslation();
  return (
    <span className={`pill ${online ? "pill-success" : "pill-muted"}`}>
      <span className="dot" aria-hidden="true" />
      {t(online ? "status.online" : "status.offline")}
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const { t } = useTranslation();
  if (status === "active") return null;
  return (
    <span className={`pill ${status === "pending" ? "pill-warning" : "pill-danger"}`}>
      {t(`status.${status}`)}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity?: string }) {
  const { t } = useTranslation();
  const key = severity && ["Critical", "Important", "Moderate", "Low"].includes(severity) ? severity : "none";
  return <span className={`sev sev-${key.toLowerCase()}`}>{t(`severity.${key}`)}</span>;
}

export function PlatformIcon({ platform }: { platform: string }) {
  const { t } = useTranslation();
  const label = t(`machines.platform.${platform}`, { defaultValue: platform });
  return (
    <span className="platform-icon" title={label} aria-label={label} role="img">
      {platform === "windows" ? (
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M3 5.5 10.5 4.5v7H3zM12 4.3 21 3v8.5h-9zM3 12.5h7.5v7L3 18.5zM12 12.5h9V21l-9-1.3z" />
        </svg>
      ) : (
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M16.4 12.6c0-2.2 1.8-3.2 1.9-3.3-1-1.5-2.6-1.7-3.2-1.7-1.4-.1-2.6.8-3.3.8-.7 0-1.7-.8-2.9-.8-1.5 0-2.9.9-3.6 2.2-1.6 2.7-.4 6.6 1.1 8.8.8 1.1 1.6 2.3 2.8 2.2 1.1 0 1.5-.7 2.9-.7 1.3 0 1.7.7 2.9.7 1.2 0 2-1.1 2.7-2.2.9-1.2 1.2-2.4 1.2-2.5 0 0-2.3-.9-2.5-3.5ZM14.2 6.1c.6-.7 1-1.7.9-2.7-.9 0-1.9.6-2.5 1.3-.6.6-1 1.6-.9 2.6 1 .1 1.9-.5 2.5-1.2Z" />
        </svg>
      )}
    </span>
  );
}

const CVSS_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/** NVD/CVSS önem derecesi rozeti (Kritik, Yüksek, Orta, Düşük). */
export function CvssBadge({ severity }: { severity?: string }) {
  const { t } = useTranslation();
  const key = severity && CVSS_SEVERITIES.includes(severity) ? severity : "UNKNOWN";
  return <span className={`sev cvss-${key.toLowerCase()}`}>{t(`cvss.${key}`)}</span>;
}

export function RiskBadge({ score }: { score: number }) {
  const { t } = useTranslation();
  const level = riskLevel(score);
  return (
    <span className={`risk risk-${level}`} title={t(`risk.${level}`)}>
      <span className="risk-bar" aria-hidden="true">
        <span style={{ width: `${Math.min(100, Math.max(4, score))}%` }} />
      </span>
      <span className="risk-value">{Math.round(score)}</span>
      <span className="visually-hidden">{t(`risk.${level}`)}</span>
    </span>
  );
}

export function KevBadge({ ransomware }: { ransomware?: boolean }) {
  const { t } = useTranslation();
  return (
    <span
      className="pill pill-danger kev"
      title={t(ransomware ? "vulns.kevRansomwareHint" : "vulns.kevHint")}
    >
      KEV{ransomware ? " · " + t("vulns.ransomware") : ""}
    </span>
  );
}
