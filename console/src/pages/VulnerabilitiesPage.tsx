import { createColumnHelper, type PaginationState, type SortingState } from "@tanstack/react-table";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";
import type { Page, VulnListItem } from "../api/client";
import { useApi } from "../api/useApi";
import { CvssBadge, KevBadge, RiskBadge } from "../components/Badges";
import { DataTable } from "../components/DataTable";
import { PAGE_SIZES } from "../components/pageSizes";
import { formatDate, formatNumber, formatPercent } from "../format";
import { useListParams } from "../hooks/useListParams";
import { reportUrl } from "../reports";

const col = createColumnHelper<VulnListItem>();

export function SourceTags({ os, app }: { os: boolean; app: boolean }) {
  const { t } = useTranslation();
  return (
    <span className="tag-list">
      {os && <span className="tag">{t("vulns.kindOs")}</span>}
      {app && <span className="tag">{t("vulns.kindApp")}</span>}
    </span>
  );
}

export function EpssValue({ value }: { value: number | null }) {
  const { t, i18n } = useTranslation();
  if (value === null) return <span className="muted">—</span>;
  return (
    <span title={t("vulns.epssHint")} className="mono">
      {formatPercent(value * 100, i18n.language)}
    </span>
  );
}

export function VulnerabilitiesPage() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const p = useListParams();
  const lng = i18n.language;

  const q = p.get("q");
  const severity = p.get("severity");
  const kind = p.get("kind");
  const kev = p.get("kev") === "true";
  const sort = p.get("sort", "risk");
  const desc = p.get("desc") !== "false";
  const pageSize = PAGE_SIZES.includes(Number(p.get("size"))) ? Number(p.get("size")) : 50;
  const pageIndex = Math.max(0, Number(p.get("page", "1")) - 1);

  const [search, setSearch] = useState(q);
  useEffect(() => {
    const h = window.setTimeout(() => {
      if (search !== q) p.update({ q: search, page: null });
    }, 300);
    return () => window.clearTimeout(h);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  const filters = { q, severity, kind, kev: kev ? "true" : "" };
  const query = new URLSearchParams({
    ...filters,
    sort,
    desc: String(desc),
    page: String(pageIndex + 1),
    page_size: String(pageSize),
  });
  const [list, reload] = useApi<Page<VulnListItem>>(`/api/v1/vulnerabilities?${query}`);
  const sorting: SortingState = [{ id: sort, desc }];
  const pagination: PaginationState = { pageIndex, pageSize };

  const columns = useMemo(
    () => [
      col.accessor("cve_id", {
        id: "cve",
        header: t("vulns.col.cve"),
        cell: (c) => (
          <Link
            to={`/zafiyetler/${c.getValue()}`}
            className="mono strong"
            onClick={(e) => e.stopPropagation()}
          >
            {c.getValue()}
          </Link>
        ),
      }),
      col.accessor("title", {
        header: t("vulns.col.title"),
        enableSorting: false,
        cell: (c) => (
          <span className="cell-wrap">
            {c.getValue() || <span className="muted">—</span>}{" "}
            {c.row.original.kev && <KevBadge ransomware={c.row.original.ransomware} />}
            {!c.row.original.kev && c.row.original.exploited && (
              <span className="pill pill-danger" title={t("vulns.exploitedHint")}>
                {t("vulns.exploited")}
              </span>
            )}
          </span>
        ),
      }),
      col.accessor("severity", {
        header: t("vulns.col.severity"),
        enableSorting: false,
        cell: (c) => <CvssBadge severity={c.getValue()} />,
      }),
      col.accessor("cvss_score", {
        id: "cvss",
        header: t("vulns.col.cvss"),
        cell: (c) => <span className="mono">{c.getValue()?.toFixed(1) ?? "—"}</span>,
      }),
      col.accessor("epss", {
        header: t("vulns.col.epss"),
        cell: (c) => <EpssValue value={c.getValue()} />,
      }),
      col.accessor("risk_score", {
        id: "risk",
        header: t("vulns.col.risk"),
        cell: (c) => <RiskBadge score={c.getValue()} />,
      }),
      col.accessor("affected_machines", {
        id: "affected",
        header: t("vulns.col.affected"),
        cell: (c) => formatNumber(c.getValue(), lng),
      }),
      col.display({
        id: "kind",
        header: t("vulns.col.kind"),
        cell: (c) => <SourceTags os={c.row.original.os} app={c.row.original.app} />,
      }),
      col.accessor("published_at", {
        id: "published",
        header: t("vulns.col.published"),
        cell: (c) => formatDate(c.getValue(), lng),
      }),
    ],
    [t, lng],
  );

  const data = list.status === "ok" ? list.data : null;
  const exportFilters = { q, severity, kind, kev: kev ? "true" : "" };

  return (
    <div className="page">
      <header className="page-header page-header-row">
        <div>
          <h1>{t("vulns.title")}</h1>
          <p className="muted">{t("vulns.subtitle")}</p>
        </div>
        <div className="report-actions" aria-label={t("vulns.export")}>
          {(["xlsx", "pdf", "csv"] as const).map((f) => (
            <a
              key={f}
              className="btn btn-ghost btn-sm"
              href={reportUrl("vulnerabilities", f, lng, exportFilters)}
              download
            >
              {t(`reports.formats.${f}`)}
            </a>
          ))}
        </div>
      </header>

      <section className="card">
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
              placeholder={t("vulns.searchPlaceholder")}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </label>
          <select
            className="select"
            aria-label={t("vulns.severity")}
            value={severity}
            onChange={(e) => p.update({ severity: e.target.value, page: null })}
          >
            <option value="">
              {t("vulns.severity")}: {t("common.all")}
            </option>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
              <option key={s} value={s}>
                {t(`cvss.${s}`)}
              </option>
            ))}
          </select>
          <select
            className="select"
            aria-label={t("vulns.kind")}
            value={kind}
            onChange={(e) => p.update({ kind: e.target.value, page: null })}
          >
            <option value="">
              {t("vulns.kind")}: {t("common.all")}
            </option>
            <option value="os">{t("vulns.kindOs")}</option>
            <option value="app">{t("vulns.kindApp")}</option>
          </select>
          <label className="filter-check">
            <input
              type="checkbox"
              className="checkbox"
              checked={kev}
              onChange={(e) => p.update({ kev: e.target.checked ? "true" : null, page: null })}
            />
            {t("vulns.kevOnly")}
          </label>
        </div>

        {list.status === "error" && (
          <div className="card-body">
            <div className="alert alert-danger" role="alert">
              {t(list.error, { defaultValue: t("errors.unknown") })}{" "}
              <button type="button" className="btn btn-ghost btn-sm" onClick={reload}>
                {t("common.retry")}
              </button>
            </div>
          </div>
        )}

        <DataTable
          label={t("vulns.title")}
          data={data?.items ?? []}
          columns={columns}
          getRowId={(v) => v.cve_id}
          serverTotal={data?.total ?? 0}
          loading={list.status === "loading"}
          emptyText={q || severity || kind || kev ? t("vulns.empty") : t("vulns.noData")}
          sorting={sorting}
          onSortingChange={(u) => {
            const next = typeof u === "function" ? u(sorting) : u;
            const s = next[0];
            p.update({ sort: s?.id ?? null, desc: s && !s.desc ? "false" : null, page: null });
          }}
          pagination={pagination}
          onPaginationChange={(u) => {
            const next = typeof u === "function" ? u(pagination) : u;
            p.update({
              page: next.pageIndex > 0 ? String(next.pageIndex + 1) : null,
              size: next.pageSize !== 50 ? String(next.pageSize) : null,
            });
          }}
          onRowClick={(v) => navigate(`/zafiyetler/${v.cve_id}`)}
        />
      </section>
    </div>
  );
}
