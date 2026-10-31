import { Fragment, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { AuditEntry, Page } from "../api/client";
import { useApi } from "../api/useApi";
import { PAGE_SIZES } from "../components/pageSizes";
import { formatDateTime } from "../format";
import { useListParams } from "../hooks/useListParams";

const ACTION_GROUPS = [
  "auth.",
  "action.",
  "package.",
  "user.",
  "settings.",
  "machine.",
  "report.",
  "authz.denied",
  "agent.",
];

const RESULT_TONE = { success: "pill-success", failure: "pill-danger", denied: "pill-warning" } as const;

export function AuditPage() {
  const { t, i18n } = useTranslation();
  const p = useListParams();
  const q = p.get("q");
  const action = p.get("action");
  const result = p.get("result");
  const from = p.get("from");
  const to = p.get("to");
  const pageSize = PAGE_SIZES.includes(Number(p.get("size"))) ? Number(p.get("size")) : 50;
  const page = Math.max(1, Number(p.get("page", "1")));
  const [search, setSearch] = useState(q);
  const [open, setOpen] = useState<number | null>(null);
  useEffect(() => {
    const h = window.setTimeout(() => {
      if (search !== q) p.update({ q: search, page: null });
    }, 300);
    return () => window.clearTimeout(h);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  let tz = "";
  try {
    tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    // saat dilimi alınamazsa sunucu UTC kullanır
  }
  const filters = { q, action, result, from, to, tz };
  const query = new URLSearchParams({ ...filters, page: String(page), page_size: String(pageSize) });
  const [list] = useApi<Page<AuditEntry>>(`/api/v1/audit?${query}`);
  const data = list.status === "ok" ? list.data : null;
  const lastPage = data ? Math.max(1, Math.ceil(data.total / pageSize)) : 1;
  const exportUrl = (format: string) =>
    `/api/v1/audit/export?${new URLSearchParams({ ...filters, format, lang: i18n.language === "en" ? "en" : "tr" })}`;

  return (
    <div className="page">
      <header className="page-header page-header-row">
        <div>
          <h1>{t("audit.title")}</h1>
          <p className="muted">{t("audit.subtitle")}</p>
        </div>
        <div className="report-actions" aria-label={t("audit.export")}>
          <a className="btn btn-ghost btn-sm" href={exportUrl("xlsx")} download>
            {t("reports.formats.xlsx")}
          </a>
          <a className="btn btn-ghost btn-sm" href={exportUrl("csv")} download>
            {t("reports.formats.csv")}
          </a>
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
              placeholder={t("audit.searchPlaceholder")}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </label>
          <select
            className="select"
            aria-label={t("audit.action")}
            value={action}
            onChange={(e) => p.update({ action: e.target.value, page: null })}
          >
            <option value="">
              {t("audit.action")}: {t("common.all")}
            </option>
            {ACTION_GROUPS.map((g) => (
              <option key={g} value={g}>
                {t(`audit.actionGroups.${g}`)}
              </option>
            ))}
          </select>
          <select
            className="select"
            aria-label={t("audit.result")}
            value={result}
            onChange={(e) => p.update({ result: e.target.value, page: null })}
          >
            <option value="">
              {t("audit.result")}: {t("common.all")}
            </option>
            {(["success", "failure", "denied"] as const).map((r) => (
              <option key={r} value={r}>
                {t(`audit.results.${r}`)}
              </option>
            ))}
          </select>
          <label className="filter-check">
            {t("audit.from")}
            <input
              className="input input-sm"
              type="date"
              value={from}
              onChange={(e) => p.update({ from: e.target.value, page: null })}
            />
          </label>
          <label className="filter-check">
            {t("audit.to")}
            <input
              className="input input-sm"
              type="date"
              value={to}
              onChange={(e) => p.update({ to: e.target.value, page: null })}
            />
          </label>
        </div>
        <div className="table-wrap">
          <table
            className="table"
            aria-label={t("audit.title")}
            aria-busy={list.status === "loading" || undefined}
          >
            <thead>
              <tr>
                <th>{t("audit.col.time")}</th>
                <th>{t("audit.col.actor")}</th>
                <th>{t("audit.col.action")}</th>
                <th>{t("audit.col.target")}</th>
                <th>{t("audit.col.result")}</th>
                <th>{t("audit.col.ip")}</th>
              </tr>
            </thead>
            <tbody>
              {data && data.items.length === 0 && (
                <tr>
                  <td colSpan={6} className="table-empty">
                    {t("audit.empty")}
                  </td>
                </tr>
              )}
              {data?.items.map((e) => (
                <Fragment key={e.id}>
                  <tr className="clickable" onClick={() => setOpen(open === e.id ? null : e.id)}>
                    <td className="mono small">{formatDateTime(e.occurred_at, i18n.language)}</td>
                    <td>
                      <span className="strong">{e.actor_name || "—"}</span>{" "}
                      <span className="tag">{e.actor_type}</span>
                    </td>
                    <td className="mono small">{e.action}</td>
                    <td className="small cell-wrap">
                      {e.target_type && <span className="tag">{e.target_type}</span>}{" "}
                      <span className="mono">{e.target_id}</span>
                    </td>
                    <td>
                      <span className={`pill ${RESULT_TONE[e.result]}`}>
                        {t(`audit.results.${e.result}`)}
                      </span>
                    </td>
                    <td className="mono small">{e.source_ip}</td>
                  </tr>
                  {open === e.id && (
                    <tr className="target-output">
                      <td colSpan={6} className="stack">
                        {e.detail && (
                          <p className="small">
                            <span className="strong">{t("audit.col.detail")}:</span> {e.detail}
                          </p>
                        )}
                        <div>
                          <p className="small strong">{t("audit.params")}</p>
                          <pre className="output-block">{JSON.stringify(e.params, null, 2)}</pre>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
        <div className="pager">
          <span className="pager-range">
            {data
              ? t("table.range", {
                  from: (page - 1) * pageSize + (data.total ? 1 : 0),
                  to: Math.min(data.total, page * pageSize),
                  total: data.total,
                })
              : ""}
          </span>
          <button
            type="button"
            className="icon-btn"
            aria-label={t("table.prev")}
            disabled={page <= 1}
            onClick={() => p.update({ page: page > 2 ? String(page - 1) : null })}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="m15 18-6-6 6-6" />
            </svg>
          </button>
          <button
            type="button"
            className="icon-btn"
            aria-label={t("table.next")}
            disabled={page >= lastPage}
            onClick={() => p.update({ page: String(page + 1) })}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="m9 18 6-6-6-6" />
            </svg>
          </button>
        </div>
      </section>
    </div>
  );
}
