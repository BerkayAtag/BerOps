import { createColumnHelper, type PaginationState, type SortingState } from "@tanstack/react-table";
import { useMemo, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";
import {
  api,
  errorKey,
  type InstalledApp,
  type InstalledPatch,
  type MachineDetail,
  type MachineVuln,
  type MissingPatch,
} from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";
import {
  CvssBadge,
  KevBadge,
  OnlinePill,
  PlatformIcon,
  RiskBadge,
  SeverityBadge,
  StatusPill,
} from "../components/Badges";
import { DataTable } from "../components/DataTable";
import { formatBytes, formatDate, formatDateTime, formatNumber, formatRelative } from "../format";
import { EpssValue } from "./VulnerabilitiesPage";

type Tab = "vulns" | "missing" | "installed" | "apps";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="field-row">
      <dt>{label}</dt>
      <dd>{children || "—"}</dd>
    </div>
  );
}

const severityRank: Record<string, number> = { Critical: 0, Important: 1, Moderate: 2, Low: 3 };

export function MachineDetailPage() {
  const { id = "" } = useParams();
  const { t, i18n } = useTranslation();
  const { can } = useAuth();
  const lng = i18n.language;
  const [detail, reload] = useApi<MachineDetail>(`/api/v1/machines/${id}`);
  const hasInv = detail.status === "ok" && detail.data.inventory !== null;
  const [missing] = useApi<{ items: MissingPatch[] }>(
    hasInv ? `/api/v1/machines/${id}/missing-patches` : null,
  );
  const [installed] = useApi<{ items: InstalledPatch[] }>(
    hasInv ? `/api/v1/machines/${id}/installed-patches` : null,
  );
  const [apps] = useApi<{ items: InstalledApp[] }>(hasInv ? `/api/v1/machines/${id}/apps` : null);
  const [vulns] = useApi<{ items: MachineVuln[] }>(hasInv ? `/api/v1/machines/${id}/vulnerabilities` : null);
  const [tab, setTab] = useState<Tab>("vulns");
  const [notice, setNotice] = useState<string | null>(null);

  async function rescan() {
    try {
      await api("/api/v1/machines/scan", { method: "POST", body: { machine_ids: [id] } });
      reload();
    } catch (err) {
      setNotice(t(errorKey(err), { defaultValue: t("errors.unknown") }));
    }
  }

  if (detail.status === "loading") return <p className="muted">{t("common.loading")}</p>;
  if (detail.status === "error") {
    return (
      <div className="page">
        <Link to="/makineler" className="back-link">
          ← {t("machines.title")}
        </Link>
        <div className="alert alert-danger" role="alert">
          {detail.error === "errors.not_found"
            ? t("machine.notFound")
            : t(detail.error, { defaultValue: t("errors.unknown") })}
        </div>
      </div>
    );
  }

  const { machine: m, inventory: inv, online, scan_requested_at, risk } = detail.data;
  const os = inv?.os;
  const canScan = can("machines.manage");

  return (
    <div className="page">
      <Link to="/makineler" className="back-link">
        ← {t("machines.title")}
      </Link>
      <header className="page-header page-header-row">
        <div className="title-with-icon">
          <PlatformIcon platform={m.os_platform} />
          <div>
            <h1>{m.hostname}</h1>
            <span className="pills">
              <OnlinePill online={online} />
              <StatusPill status={m.status} />
              {inv?.reboot_pending && <span className="pill pill-info">{t("machines.rebootPending")}</span>}
            </span>
          </div>
        </div>
        <button
          type="button"
          className="btn btn-primary"
          disabled={!canScan || scan_requested_at !== null}
          title={canScan ? undefined : t("common.noPermission")}
          onClick={() => void rescan()}
        >
          {t("machines.rescan")}
        </button>
      </header>

      {notice && (
        <div className="alert alert-danger" role="alert">
          {notice}
        </div>
      )}
      {scan_requested_at && (
        <div className="alert alert-info" role="status">
          {t("machine.scanPending", { time: formatRelative(scan_requested_at, lng) })}
        </div>
      )}

      {risk && (
        <section className="stat-grid" aria-label={t("machine.risk.title")}>
          <div className="stat-card tone-danger">
            <span className="stat-label">{t("machine.risk.maxRisk")}</span>
            <span className="stat-value">
              <RiskBadge score={risk.max_risk} />
            </span>
          </div>
          <div className="stat-card tone-warning">
            <span className="stat-label">{t("machine.risk.vulns")}</span>
            <span className="stat-value">{formatNumber(risk.vuln_count, lng)}</span>
          </div>
          <div className="stat-card tone-danger">
            <span className="stat-label">{t("machine.risk.critical")}</span>
            <span className="stat-value">{formatNumber(risk.critical_count, lng)}</span>
          </div>
          <div className="stat-card tone-danger">
            <span className="stat-label">{t("machine.risk.kev")}</span>
            <span className="stat-value">{formatNumber(risk.kev_count, lng)}</span>
          </div>
        </section>
      )}

      <div className="detail-grid">
        <section className="card">
          <div className="card-header">
            <h2>{t("machine.general")}</h2>
          </div>
          <dl className="card-body fields">
            <Field label={t("machine.field.os")}>
              {(os?.name ?? m.os_name) + " " + (os?.version ?? m.os_version)}
            </Field>
            <Field label={t("machine.field.build")}>
              <span className="mono">{os?.build ?? m.os_build}</span>
            </Field>
            <Field label={t("machine.field.ip")}>
              <span className="mono">{m.ip_addresses.join(", ")}</span>
            </Field>
            <Field label={t("machine.field.ou")}>{m.ad_ou}</Field>
            {os?.domain && <Field label={t("machine.field.domain")}>{os.domain}</Field>}
            <Field label={t("machine.field.lastSeen")}>
              {formatDateTime(m.last_seen_at, lng)} ({formatRelative(m.last_seen_at, lng, t("common.never"))})
            </Field>
            <Field label={t("machine.field.agentVersion")}>
              <span className="mono">{m.agent_version}</span>
            </Field>
            <Field label={t("machine.field.enrolledAt")}>{formatDateTime(m.enrolled_at, lng)}</Field>
            {os?.model && (
              <Field label={t("machine.field.hardware")}>
                {`${os.manufacturer ?? ""} ${os.model}`.trim()}
              </Field>
            )}
            {os?.serial_number && (
              <Field label={t("machine.field.serial")}>
                <span className="mono">{os.serial_number}</span>
              </Field>
            )}
            {os?.cpu_model && (
              <Field label={t("machine.field.cpu")}>{`${os.cpu_model} (${os.cpu_cores ?? "?"})`}</Field>
            )}
            {os?.memory_bytes ? (
              <Field label={t("machine.field.memory")}>{formatBytes(os.memory_bytes, lng)}</Field>
            ) : null}
            {os?.last_boot_at && (
              <Field label={t("machine.field.lastBoot")}>{formatDateTime(os.last_boot_at, lng)}</Field>
            )}
          </dl>
        </section>

        <section className="card">
          <div className="card-header">
            <h2>{t("machine.inventoryStatus")}</h2>
          </div>
          {!inv ? (
            <p className="card-body muted">{t("machine.noInventoryYet")}</p>
          ) : (
            <dl className="card-body fields">
              <Field label={t("machine.field.lastInventory")}>{formatDateTime(inv.received_at, lng)}</Field>
              <Field label={t("machine.field.lastFull")}>{formatDateTime(inv.last_full_at, lng)}</Field>
              <Field label={t("machine.field.missingSource")}>
                {t(`machine.scanSource.${inv.missing_scan_source || "none"}`)}
              </Field>
              <Field label={t("machine.field.missingScannedAt")}>
                {formatDateTime(inv.missing_scanned_at, lng)}
              </Field>
              <Field label={t("machine.field.scanDuration")}>
                {t("common.seconds", { n: (inv.scan_duration_ms / 1000).toFixed(1) })}
              </Field>
              <Field label={t("machine.field.certExpires")}>{formatDate(m.cert_expires_at, lng)}</Field>
              {inv.scan_errors.length > 0 && (
                <Field label={t("machine.field.scanErrors")}>
                  <ul className="error-list">
                    {inv.scan_errors.map((e) => (
                      <li key={e}>{e}</li>
                    ))}
                  </ul>
                </Field>
              )}
              {m.last_errors.length > 0 && (
                <Field label={t("machine.field.agentErrors")}>
                  <ul className="error-list">
                    {m.last_errors.map((e) => (
                      <li key={e}>{e}</li>
                    ))}
                  </ul>
                </Field>
              )}
            </dl>
          )}
        </section>
      </div>

      {inv && (
        <section className="card">
          <div className="tabs" role="tablist">
            {(
              [
                ["vulns", risk?.vuln_count ?? 0],
                ["missing", inv.missing_count],
                ["installed", inv.installed_patch_count],
                ["apps", inv.app_count],
              ] as const
            ).map(([k, n]) => (
              <button
                key={k}
                type="button"
                role="tab"
                aria-selected={tab === k}
                className={`tab${tab === k ? " active" : ""}`}
                onClick={() => setTab(k)}
              >
                {t(`machine.tabs.${k}`, { count: n })}
              </button>
            ))}
          </div>
          <div role="tabpanel">
            {tab === "vulns" && <VulnTable rows={vulns.status === "ok" ? vulns.data.items : []} />}
            {tab === "missing" && <MissingTable rows={missing.status === "ok" ? missing.data.items : []} />}
            {tab === "installed" && (
              <InstalledTable rows={installed.status === "ok" ? installed.data.items : []} />
            )}
            {tab === "apps" && <AppsTable rows={apps.status === "ok" ? apps.data.items : []} />}
          </div>
        </section>
      )}
    </div>
  );
}

const vcol = createColumnHelper<MachineVuln>();

function VulnTable({ rows }: { rows: MachineVuln[] }) {
  const { t, i18n } = useTranslation();
  const [sorting, setSorting] = useState<SortingState>([{ id: "risk", desc: true }]);
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });
  const columns = useMemo(
    () => [
      vcol.accessor("risk_score", {
        id: "risk",
        header: t("vulns.col.risk"),
        cell: (c) => <RiskBadge score={c.getValue()} />,
      }),
      vcol.accessor("cve_id", {
        header: t("vulns.col.cve"),
        cell: (c) => (
          <Link to={`/zafiyetler/${c.getValue()}`} className="mono strong">
            {c.getValue()}
          </Link>
        ),
      }),
      vcol.accessor("title", {
        header: t("vulns.col.title"),
        cell: (c) => (
          <span className="cell-wrap">
            {c.getValue() || "—"} {c.row.original.kev && <KevBadge />}
          </span>
        ),
      }),
      vcol.accessor((r) => r.cvss_score ?? -1, {
        id: "cvss",
        header: t("vulns.col.cvss"),
        cell: (c) => (
          <span className="pills">
            <CvssBadge severity={c.row.original.severity} />
            <span className="mono">{c.row.original.cvss_score?.toFixed(1) ?? ""}</span>
          </span>
        ),
      }),
      vcol.accessor((r) => r.epss ?? -1, {
        id: "epss",
        header: t("vulns.col.epss"),
        cell: (c) => <EpssValue value={c.row.original.epss} />,
      }),
      vcol.accessor((r) => r.sources.join(","), {
        id: "sources",
        header: t("vulns.col.kind"),
        cell: (c) => (
          <span className="tag-list">
            {c.row.original.sources.map((s) => (
              <span key={s} className="tag" title={c.row.original.refs.join(", ")}>
                {t(`source.${s}`, { defaultValue: s })}
              </span>
            ))}
          </span>
        ),
      }),
      vcol.accessor((r) => r.fixed_by.join(", "), {
        id: "fixed_by",
        header: t("vulns.col.fixedBy"),
        cell: (c) => <span className="mono small cell-wrap">{c.getValue()}</span>,
      }),
      vcol.accessor("first_seen_at", {
        header: t("vulns.col.firstSeen"),
        cell: (c) => formatDate(c.getValue(), i18n.language),
      }),
    ],
    [t, i18n.language],
  );
  return (
    <DataTable
      label={t("machine.tabs.vulns", { count: rows.length })}
      data={rows}
      columns={columns}
      getRowId={(r) => r.cve_id}
      sorting={sorting}
      onSortingChange={setSorting}
      pagination={pagination}
      onPaginationChange={setPagination}
      emptyText={t("machine.vulnsNone")}
    />
  );
}

const mcol = createColumnHelper<MissingPatch>();

function MissingTable({ rows }: { rows: MissingPatch[] }) {
  const { t, i18n } = useTranslation();
  const [sorting, setSorting] = useState<SortingState>([{ id: "severity", desc: false }]);
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });
  const columns = useMemo(
    () => [
      mcol.accessor((r) => severityRank[r.severity ?? ""] ?? 9, {
        id: "severity",
        header: t("machine.missing.severity"),
        cell: (c) => <SeverityBadge severity={c.row.original.severity} />,
      }),
      mcol.accessor("title", {
        header: t("machine.missing.title"),
        cell: (c) => (
          <span className="cell-wrap">
            {c.row.original.support_url ? (
              <a href={c.row.original.support_url} target="_blank" rel="noreferrer noopener">
                {c.getValue()}
              </a>
            ) : (
              c.getValue()
            )}
          </span>
        ),
      }),
      mcol.accessor((r) => r.kb || r.version || "", { id: "kb", header: t("machine.missing.kb") }),
      mcol.accessor("classification", { header: t("machine.missing.classification") }),
      mcol.accessor((r) => (r.cves ?? []).length, {
        id: "cves",
        header: t("machine.missing.cves"),
        cell: (c) => {
          const cves = c.row.original.cves ?? [];
          const rest = cves.slice(2);
          return (
            <span className="cve-list">
              {cves.slice(0, 2).map((cve) => (
                <a
                  key={cve}
                  href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="mono"
                >
                  {cve}
                </a>
              ))}
              {rest.length > 0 && (
                <span className="more" title={rest.join(", ")}>
                  +{rest.length}
                </span>
              )}
            </span>
          );
        },
      }),
      mcol.accessor((r) => r.released_at ?? "", {
        id: "released",
        header: t("machine.missing.released"),
        cell: (c) => formatDate(c.row.original.released_at, i18n.language),
      }),
      mcol.accessor("reboot_required", {
        header: t("machine.missing.reboot"),
        cell: (c) => (c.getValue() ? t("common.yes") : t("common.no")),
      }),
      mcol.accessor((r) => r.size_bytes ?? 0, {
        id: "size",
        header: t("machine.missing.size"),
        cell: (c) => formatBytes(c.getValue(), i18n.language),
      }),
    ],
    [t, i18n.language],
  );
  return (
    <DataTable
      label={t("machine.tabs.missing", { count: rows.length })}
      data={rows}
      columns={columns}
      getRowId={(r) => r.id}
      sorting={sorting}
      onSortingChange={setSorting}
      pagination={pagination}
      onPaginationChange={setPagination}
      emptyText={t("machine.missing.none")}
    />
  );
}

const icol = createColumnHelper<InstalledPatch>();

function InstalledTable({ rows }: { rows: InstalledPatch[] }) {
  const { t, i18n } = useTranslation();
  const [sorting, setSorting] = useState<SortingState>([{ id: "installed_on", desc: true }]);
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });
  const columns = useMemo(
    () => [
      icol.accessor("id", {
        header: t("machine.installed.id"),
        cell: (c) => <span className="mono">{c.getValue()}</span>,
      }),
      icol.accessor((r) => r.title ?? "", { id: "title", header: t("machine.installed.title") }),
      icol.accessor((r) => r.installed_on ?? "", {
        id: "installed_on",
        header: t("machine.installed.installedOn"),
        cell: (c) => formatDate(c.getValue(), i18n.language),
      }),
      icol.accessor("source", { header: t("machine.installed.source") }),
    ],
    [t, i18n.language],
  );
  return (
    <DataTable
      label={t("machine.tabs.installed", { count: rows.length })}
      data={rows}
      columns={columns}
      getRowId={(r) => r.id}
      sorting={sorting}
      onSortingChange={setSorting}
      pagination={pagination}
      onPaginationChange={setPagination}
    />
  );
}

const acol = createColumnHelper<InstalledApp>();

function AppsTable({ rows }: { rows: InstalledApp[] }) {
  const { t, i18n } = useTranslation();
  const [search, setSearch] = useState("");
  const [sorting, setSorting] = useState<SortingState>([{ id: "name", desc: false }]);
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });
  const filtered = useMemo(() => {
    const q = search.trim().toLocaleLowerCase(i18n.language === "tr" ? "tr-TR" : "en");
    if (!q) return rows;
    return rows.filter((a) =>
      [a.name, a.version, a.publisher ?? ""].some((v) =>
        v.toLocaleLowerCase(i18n.language === "tr" ? "tr-TR" : "en").includes(q),
      ),
    );
  }, [rows, search, i18n.language]);
  const columns = useMemo(
    () => [
      acol.accessor("name", {
        header: t("machine.apps.name"),
        cell: (c) => <span className="strong">{c.getValue()}</span>,
      }),
      acol.accessor("version", {
        header: t("machine.apps.version"),
        cell: (c) => <span className="mono">{c.getValue()}</span>,
      }),
      acol.accessor((r) => r.publisher ?? "", { id: "publisher", header: t("machine.apps.publisher") }),
      acol.accessor("source", { header: t("machine.apps.source") }),
      acol.accessor((r) => r.install_date ?? "", {
        id: "install_date",
        header: t("machine.apps.installDate"),
        cell: (c) => formatDate(c.getValue(), i18n.language),
      }),
      acol.accessor((r) => r.scope ?? "", {
        id: "scope",
        header: t("machine.apps.scope"),
        cell: (c) => {
          const v = c.getValue();
          return v.startsWith("user:")
            ? `${t("machine.scope.user")} (${v.slice(5)})`
            : t("machine.scope.machine");
        },
      }),
    ],
    [t, i18n.language],
  );
  return (
    <>
      <div className="toolbar">
        <label className="search">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="11" cy="11" r="7" />
            <path d="m20 20-3.5-3.5" />
          </svg>
          <input
            className="input"
            type="search"
            aria-label={t("common.search")}
            placeholder={t("machine.apps.searchPlaceholder")}
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPagination((p) => ({ ...p, pageIndex: 0 }));
            }}
          />
        </label>
      </div>
      <DataTable
        label={t("machine.tabs.apps", { count: rows.length })}
        data={filtered}
        columns={columns}
        getRowId={(r) => `${r.name}|${r.version}|${r.source}|${r.scope}|${r.install_location}`}
        sorting={sorting}
        onSortingChange={setSorting}
        pagination={pagination}
        onPaginationChange={setPagination}
      />
    </>
  );
}
