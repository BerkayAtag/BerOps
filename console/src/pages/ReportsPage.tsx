import { useState } from "react";
import { useTranslation } from "react-i18next";
import { reportUrl, type ReportFormat, type ReportType } from "../reports";

const REPORTS: ReportType[] = ["compliance", "vulnerabilities", "missing-patches", "apps"];
const FORMATS: ReportFormat[] = ["pdf", "xlsx", "csv"];

function ReportCard({ type, lang }: { type: ReportType; lang: string }) {
  const { t } = useTranslation();
  const [platform, setPlatform] = useState("");
  const [severity, setSeverity] = useState("");
  const [kev, setKev] = useState(false);
  const [search, setSearch] = useState("");

  const filters: Record<string, string> = { severity, q: search.trim(), kev: kev ? "true" : "" };
  if (type !== "vulnerabilities") filters.platform = platform;

  return (
    <section className="card report-card">
      <div className="card-header">
        <h2>{t(`reports.${type}.title`)}</h2>
      </div>
      <div className="card-body">
        <p className="muted small">{t(`reports.${type}.desc`)}</p>
        <div className="report-filters">
          {type !== "vulnerabilities" && (
            <label>
              {t("reports.platform")}
              <select
                className="select select-sm"
                value={platform}
                onChange={(e) => setPlatform(e.target.value)}
              >
                <option value="">{t("common.all")}</option>
                <option value="windows">{t("machines.platform.windows")}</option>
                <option value="darwin">{t("machines.platform.darwin")}</option>
              </select>
            </label>
          )}
          {type === "vulnerabilities" && (
            <>
              <label>
                {t("reports.severity")}
                <select
                  className="select select-sm"
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                >
                  <option value="">{t("common.all")}</option>
                  {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
                    <option key={s} value={s}>
                      {t(`cvss.${s}`)}
                    </option>
                  ))}
                </select>
              </label>
              <label className="filter-check">
                <input
                  type="checkbox"
                  className="checkbox"
                  checked={kev}
                  onChange={(e) => setKev(e.target.checked)}
                />
                {t("reports.kevOnly")}
              </label>
            </>
          )}
          {type === "missing-patches" && (
            <label>
              {t("reports.severity")}
              <select
                className="select select-sm"
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
              >
                <option value="">{t("common.all")}</option>
                {["Critical", "Important", "Moderate", "Low"].map((s) => (
                  <option key={s} value={s}>
                    {t(`severity.${s}`)}
                  </option>
                ))}
              </select>
            </label>
          )}
          {type === "apps" && (
            <label>
              {t("reports.search")}
              <input className="input input-sm" value={search} onChange={(e) => setSearch(e.target.value)} />
            </label>
          )}
        </div>
        <div className="report-actions">
          {FORMATS.map((f) => (
            <a
              key={f}
              className={`btn btn-sm ${f === "pdf" ? "btn-primary" : "btn-ghost"}`}
              href={reportUrl(type, f, lang, filters)}
              download
            >
              {t(`reports.formats.${f}`)}
            </a>
          ))}
        </div>
      </div>
    </section>
  );
}

export function ReportsPage() {
  const { t, i18n } = useTranslation();
  const [lang, setLang] = useState(i18n.language === "en" ? "en" : "tr");
  return (
    <div className="page">
      <header className="page-header page-header-row">
        <div>
          <h1>{t("reports.title")}</h1>
          <p className="muted">{t("reports.subtitle")}</p>
        </div>
        <label className="report-filters">
          <span className="muted small">{t("reports.lang")}</span>
          <select className="select select-sm" value={lang} onChange={(e) => setLang(e.target.value)}>
            <option value="tr">Türkçe</option>
            <option value="en">English</option>
          </select>
        </label>
      </header>
      <div className="report-grid">
        {REPORTS.map((r) => (
          <ReportCard key={r} type={r} lang={lang} />
        ))}
      </div>
      <p className="muted small">{t("reports.pdfNote")}</p>
    </div>
  );
}
