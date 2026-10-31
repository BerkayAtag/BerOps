import { useTranslation } from "react-i18next";
import type { ComplianceSample } from "../api/client";
import { formatDate, formatPercent } from "../format";

/** Günlük uyumluluk oranının (tam yamalı / envanteri olan) çizgi grafiği. */
export function TrendChart({ samples }: { samples: ComplianceSample[] }) {
  const { t, i18n } = useTranslation();
  const points = samples
    .filter((s) => s.with_inventory > 0)
    .map((s) => ({ day: s.day, pct: (s.fully_patched / s.with_inventory) * 100 }));
  if (points.length < 2) return <p className="muted small">{t("home.trendEmpty")}</p>;

  const w = 300;
  const h = 100;
  const x = (i: number) => (i / (points.length - 1)) * w;
  const y = (pct: number) => h - (pct / 100) * h;
  const line = points
    .map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(p.pct).toFixed(1)}`)
    .join(" ");
  const area = `${line} L${w},${h} L0,${h} Z`;
  const last = points[points.length - 1]!;
  const label = `${t("home.trend")}: ${formatPercent(last.pct, i18n.language)}`;

  return (
    <div>
      <div className="trend-chart" role="img" aria-label={label}>
        <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" aria-hidden="true">
          {[25, 50, 75].map((g) => (
            <line
              key={g}
              className="trend-grid"
              x1="0"
              x2={w}
              y1={y(g)}
              y2={y(g)}
              vectorEffect="non-scaling-stroke"
            />
          ))}
          <path className="trend-area" d={area} />
          <path className="trend-line" d={line} vectorEffect="non-scaling-stroke" />
        </svg>
      </div>
      <div className="trend-axis">
        <span>{formatDate(points[0]!.day, i18n.language)}</span>
        <span className="strong">{formatPercent(last.pct, i18n.language)}</span>
        <span>{formatDate(last.day, i18n.language)}</span>
      </div>
    </div>
  );
}
