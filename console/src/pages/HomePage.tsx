import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";
import type { FleetSummary, MachineListItem, Me, Page, RiskSummary, ServerInfo } from "../api/client";
import { useApi } from "../api/useApi";
import { CvssBadge, KevBadge, OnlinePill, PlatformIcon, RiskBadge, StatusPill } from "../components/Badges";
import { CopyField } from "../components/CopyField";
import { TrendChart } from "../components/TrendChart";
import { formatNumber, formatPercent, formatRelative } from "../format";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;

function RiskSection() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const lng = i18n.language;
  const [risk] = useApi<RiskSummary>("/api/v1/dashboard/risk");
  if (risk.status !== "ok") return null;
  const r = risk.data;
  const sevTotal = SEVERITIES.reduce((n, s) => n + (r.by_severity[s] ?? 0), 0);
  const stats = [
    { key: "home.distinctCves", value: r.distinct_cves, tone: "neutral", to: "/zafiyetler" },
    { key: "home.urgentCves", value: r.urgent_cves, tone: "danger", to: "/zafiyetler?sort=risk" },
    { key: "home.kevMachines", value: r.kev_machines, tone: "danger", to: "/zafiyetler?kev=true" },
    {
      key: "home.avgRisk",
      value: Math.round(r.avg_machine_risk),
      tone: "warning",
      to: "/makineler?sort=risk&desc=true",
    },
  ] as const;

  return (
    <>
      <h2 className="section-title">{t("home.riskTitle")}</h2>
      <section className="stat-grid" aria-live="polite">
        {stats.map((st) => (
          <Link key={st.key} to={st.to} className={`stat-card tone-${st.tone}`}>
            <span className="stat-label">{t(st.key)}</span>
            <span className="stat-value">{formatNumber(st.value, lng)}</span>
          </Link>
        ))}
      </section>
      <div className="detail-grid">
        <section className="card">
          <div className="card-header">
            <h2>{t("home.trend")}</h2>
          </div>
          <div className="card-body stack">
            <TrendChart samples={r.trend} />
            <p className="muted small">{t("home.trendHelp")}</p>
          </div>
        </section>
        <section className="card">
          <div className="card-header">
            <h2>{t("home.bySeverity")}</h2>
          </div>
          <div className="card-body sev-bars">
            {sevTotal === 0 && <p className="muted small">{t("home.noVulns")}</p>}
            {sevTotal > 0 &&
              SEVERITIES.filter((s) => (r.by_severity[s] ?? 0) > 0 || s !== "UNKNOWN").map((s) => {
                const n = r.by_severity[s] ?? 0;
                return (
                  <Link
                    key={s}
                    to={s === "UNKNOWN" ? "/zafiyetler" : `/zafiyetler?severity=${s}`}
                    className="sev-bar-row"
                  >
                    <CvssBadge severity={s} />
                    <div className="gauge-bar">
                      <div
                        className={`gauge-fill cvss-${s.toLowerCase()}`}
                        style={{ width: `${(n / sevTotal) * 100}%` }}
                      />
                    </div>
                    <span className="dist-value">{formatNumber(n, lng)}</span>
                  </Link>
                );
              })}
          </div>
        </section>
      </div>
      <div className="detail-grid">
        <section className="card">
          <div className="card-header card-header-row">
            <h2>{t("home.topCves")}</h2>
            <Link to="/zafiyetler" className="small">
              {t("home.viewAll")} →
            </Link>
          </div>
          {r.top_cves.length === 0 ? (
            <p className="card-body muted small">{t("home.noVulns")}</p>
          ) : (
            <ul className="list-rows">
              {r.top_cves.map((v) => (
                <li key={v.cve_id} className="clickable" onClick={() => navigate(`/zafiyetler/${v.cve_id}`)}>
                  <RiskBadge score={v.risk_score} />
                  <span className="grow two-line">
                    <Link
                      to={`/zafiyetler/${v.cve_id}`}
                      className="mono strong"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {v.cve_id}
                    </Link>
                    <span className="muted small" title={v.title}>
                      {v.title}
                    </span>
                  </span>
                  {v.kev && <KevBadge ransomware={v.ransomware} />}
                  <span className="tag" title={t("vulns.col.affected")}>
                    {formatNumber(v.affected_machines, lng)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section className="card">
          <div className="card-header card-header-row">
            <h2>{t("home.topMachines")}</h2>
            <Link to="/makineler?sort=risk&desc=true" className="small">
              {t("home.viewAll")} →
            </Link>
          </div>
          {r.top_machines.length === 0 ? (
            <p className="card-body muted small">{t("home.noVulns")}</p>
          ) : (
            <ul className="list-rows">
              {r.top_machines.map((m) => (
                <li key={m.id} className="clickable" onClick={() => navigate(`/makineler/${m.id}`)}>
                  <RiskBadge score={m.max_risk} />
                  <PlatformIcon platform={m.os_platform} />
                  <span className="grow strong">{m.hostname}</span>
                  {m.kev_count > 0 && <span className="tag">KEV {m.kev_count}</span>}
                  <span className="tag">
                    {t("machine.risk.vulns")}: {formatNumber(m.vuln_count, lng)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </>
  );
}

export function HomePage({ me }: { me: Me }) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const lng = i18n.language;
  const [summary, reload] = useApi<FleetSummary>("/api/v1/machines/summary");
  const [recent] = useApi<Page<MachineListItem>>("/api/v1/machines?sort=enrolled_at&desc=true&page_size=8");
  const [info] = useApi<ServerInfo>("/api/v1/server-info");
  const name = me.user.display_name || me.user.username;

  const s = summary.status === "ok" ? summary.data : null;
  const value = (n: number | undefined) => (s && n !== undefined ? formatNumber(n, lng) : "—");
  const compliance =
    s && s.with_inventory > 0 ? Math.round((s.fully_patched / s.with_inventory) * 100) : null;

  const stats = [
    { key: "home.stats.total", value: value(s?.total), tone: "neutral", to: "/makineler" },
    { key: "home.stats.online", value: value(s?.online), tone: "success", to: "/makineler?online=true" },
    {
      key: "home.stats.offline",
      value: value(s ? s.total - s.online : undefined),
      tone: "muted",
      to: "/makineler?online=false",
    },
    { key: "home.stats.pending", value: value(s?.pending), tone: "warning", to: "/makineler?status=pending" },
    {
      key: "home.missingTotal",
      value: value(s?.missing_total),
      tone: "warning",
      to: "/makineler?sort=missing_count&desc=true",
    },
    {
      key: "home.criticalMachines",
      value: value(s?.critical_machines),
      tone: "danger",
      to: "/makineler?sort=missing_critical&desc=true",
    },
    { key: "home.rebootPending", value: value(s?.reboot_pending), tone: "info", to: "/makineler" },
    { key: "home.distinctApps", value: value(s?.distinct_apps), tone: "neutral", to: "/makineler" },
  ] as const;

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>{t("home.title")}</h1>
          <p className="muted">{t("home.welcome", { name })}</p>
        </div>
      </header>

      {me.user.role === "readonly" && <div className="alert alert-info">{t("home.readonlyNotice")}</div>}
      {summary.status === "error" && (
        <div className="alert alert-danger" role="alert">
          {t(summary.error, { defaultValue: t("errors.unknown") })}{" "}
          <button type="button" className="btn btn-ghost btn-sm" onClick={reload}>
            {t("common.retry")}
          </button>
        </div>
      )}

      <section className="stat-grid" aria-live="polite">
        {stats.map((st) => (
          <Link key={st.key} to={st.to} className={`stat-card tone-${st.tone}`}>
            <span className="stat-label">{t(st.key)}</span>
            <span className="stat-value">{st.value}</span>
          </Link>
        ))}
      </section>

      <RiskSection />

      <div className="detail-grid">
        <section className="card">
          <div className="card-header">
            <h2>{t("home.compliance")}</h2>
          </div>
          <div className="card-body">
            <div
              className="gauge"
              role="img"
              aria-label={`${t("home.compliance")}: ${compliance === null ? "—" : formatPercent(compliance, lng)}`}
            >
              <div className="gauge-bar">
                <div className="gauge-fill" style={{ width: `${compliance ?? 0}%` }} />
              </div>
              <span className="gauge-value">
                {compliance === null ? "—" : formatPercent(compliance, lng)}
              </span>
            </div>
            <p className="muted small">
              {t("home.complianceHelp")}
              {s ? ` (${s.fully_patched} / ${s.with_inventory})` : ""}
            </p>
          </div>
        </section>
        <section className="card">
          <div className="card-header">
            <h2>{t("home.osDistribution")}</h2>
          </div>
          <div className="card-body stack">
            {(
              [
                ["windows", s?.windows ?? 0],
                ["darwin", s?.macos ?? 0],
              ] as const
            ).map(([p, n]) => (
              <div key={p} className="dist-row">
                <PlatformIcon platform={p} />
                <span className="dist-label">{t(`machines.platform.${p}`)}</span>
                <div className="gauge-bar">
                  <div
                    className="gauge-fill"
                    style={{ width: s && s.total ? `${(n / s.total) * 100}%` : 0 }}
                  />
                </div>
                <span className="dist-value">{formatNumber(n, lng)}</span>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="card">
        <div className="card-header card-header-row">
          <h2>{t("home.recentMachines")}</h2>
          <Link to="/makineler" className="small">
            {t("home.viewAll")} →
          </Link>
        </div>
        {recent.status === "ok" && recent.data.items.length === 0 && (
          <p className="muted card-body">{t("home.noMachines")}</p>
        )}
        {recent.status === "ok" && recent.data.items.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>{t("home.table.hostname")}</th>
                  <th>{t("home.table.os")}</th>
                  <th>{t("home.table.build")}</th>
                  <th>{t("machines.col.missing")}</th>
                  <th>{t("home.table.lastSeen")}</th>
                  <th>{t("home.table.status")}</th>
                </tr>
              </thead>
              <tbody>
                {recent.data.items.map((m) => (
                  <tr key={m.id} className="clickable" onClick={() => navigate(`/makineler/${m.id}`)}>
                    <td>
                      <span className="cell-host">
                        <PlatformIcon platform={m.os_platform} />
                        <span className="strong">{m.hostname}</span>
                      </span>
                    </td>
                    <td>
                      {m.os_name} {m.os_version}
                    </td>
                    <td className="mono">{m.os_build}</td>
                    <td>{m.inventory_at ? m.missing_count : "—"}</td>
                    <td>{formatRelative(m.last_seen_at, lng, t("common.never"))}</td>
                    <td>
                      <span className="pills">
                        <OnlinePill online={m.online} />
                        <StatusPill status={m.status} />
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {info.status === "ok" && (
        <section className="card">
          <div className="card-header">
            <h2>{t("home.agentSetup")}</h2>
          </div>
          <div className="card-body stack">
            <p className="muted">{t("home.agentSetupHint")}</p>
            <CopyField label={t("home.agentUrl")} value={info.data.agent_url} />
            <CopyField label={t("home.caFingerprint")} value={info.data.ca_fingerprint} />
            <p className="muted small">
              {t("home.serverVersion")}: <span className="mono">{info.data.version}</span>
            </p>
          </div>
        </section>
      )}
    </div>
  );
}
