import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, errorKey, type CVEStatus, type ProductRule } from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";
import { formatDateTime, formatNumber, formatRelative } from "../format";

const emptyRule = { name: "", publisher: "", identifier: "", vendor: "", product: "" };

export function CveSettingsPage() {
  const { t, i18n } = useTranslation();
  const { can } = useAuth();
  const lng = i18n.language;
  const canWrite = can("settings.write");
  const [status, reloadStatus] = useApi<CVEStatus>("/api/v1/cve/status");
  const [rules, reloadRules] = useApi<{ items: ProductRule[] }>("/api/v1/cve/rules");
  const [notice, setNotice] = useState<{ kind: "info" | "danger"; text: string } | null>(null);
  const [form, setForm] = useState(emptyRule);
  const [busy, setBusy] = useState(false);
  const [showBuiltin, setShowBuiltin] = useState(false);

  const fail = (err: unknown) =>
    setNotice({ kind: "danger", text: t(errorKey(err), { defaultValue: t("errors.unknown") }) });

  async function syncNow() {
    setNotice(null);
    try {
      await api("/api/v1/cve/sync", { method: "POST" });
      setNotice({ kind: "info", text: t("cveSettings.syncQueued") });
      window.setTimeout(reloadStatus, 1500);
    } catch (err) {
      fail(err);
    }
  }

  async function addRule(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      await api("/api/v1/cve/rules", { method: "POST", body: form });
      setForm(emptyRule);
      reloadRules();
      reloadStatus();
    } catch (err) {
      if (err instanceof Error && "code" in err && (err as { code: string }).code === "request.invalid") {
        setNotice({ kind: "danger", text: err.message });
      } else {
        fail(err);
      }
    } finally {
      setBusy(false);
    }
  }

  async function deleteRule(id: string) {
    setNotice(null);
    try {
      await api(`/api/v1/cve/rules/${id}`, { method: "DELETE" });
      reloadRules();
      reloadStatus();
    } catch (err) {
      fail(err);
    }
  }

  const st = status.status === "ok" ? status.data : null;
  const all = rules.status === "ok" ? rules.data.items : [];
  const custom = all.filter((r) => !r.builtin);
  const builtin = all.filter((r) => r.builtin);

  return (
    <div className="page">
      <header className="page-header page-header-row">
        <div>
          <h1>{t("cveSettings.title")}</h1>
          <p className="muted">{t("cveSettings.subtitle")}</p>
        </div>
        <button
          type="button"
          className="btn btn-primary"
          disabled={!canWrite || !st?.enabled || st?.running}
          title={canWrite ? undefined : t("common.noPermission")}
          onClick={() => void syncNow()}
        >
          {st?.running ? t("cveSettings.syncing") : t("cveSettings.syncNow")}
        </button>
      </header>

      {notice && (
        <div className={`alert alert-${notice.kind}`} role="status">
          {notice.text}
        </div>
      )}

      <section className="card">
        <div className="card-header card-header-row">
          <h2>{t("cveSettings.feeds")}</h2>
          {st && (
            <span className="muted small">
              {!st.enabled
                ? t("cveSettings.disabled")
                : st.offline
                  ? t("cveSettings.offline")
                  : t("cveSettings.online")}
            </span>
          )}
        </div>
        <div className="table-wrap">
          <table className="table" aria-label={t("cveSettings.feeds")}>
            <thead>
              <tr>
                <th>{t("cveSettings.col.feed")}</th>
                <th>{t("cveSettings.col.lastSuccess")}</th>
                <th>{t("cveSettings.col.items")}</th>
                <th>{t("cveSettings.col.duration")}</th>
                <th>{t("cveSettings.col.status")}</th>
              </tr>
            </thead>
            <tbody>
              {(st?.feeds ?? []).map((f) => (
                <tr key={f.feed}>
                  <td>
                    <span className="strong">{t(`cveSettings.feed.${f.feed}`)}</span>
                    <br />
                    <span className="muted small">{t(`cveSettings.feedDesc.${f.feed}`)}</span>
                  </td>
                  <td title={formatDateTime(f.last_success_at, lng)}>
                    {formatRelative(f.last_success_at, lng, t("cveSettings.never"))}
                  </td>
                  <td>{f.last_success_at ? formatNumber(f.item_count, lng) : "—"}</td>
                  <td>
                    {f.duration_ms ? t("common.seconds", { n: (f.duration_ms / 1000).toFixed(1) }) : "—"}
                  </td>
                  <td>
                    {f.last_error ? (
                      <span className="pill pill-danger" title={f.last_error}>
                        {t("cveSettings.error")}
                      </span>
                    ) : f.last_success_at ? (
                      <span className="pill pill-success">{t("cveSettings.ok")}</span>
                    ) : (
                      <span className="pill pill-muted">{t("cveSettings.never")}</span>
                    )}
                    {f.last_error && <p className="small muted cell-wrap">{f.last_error}</p>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {st && (
          <dl className="card-body fields">
            <div className="field-row">
              <dt>{t("cveSettings.interval")}</dt>
              <dd>{t("cveSettings.intervalValue", { n: st.sync_interval_hours })}</dd>
            </div>
            <div className="field-row">
              <dt>{t("cveSettings.apiKey")}</dt>
              <dd>{st.nvd_api_key ? t("cveSettings.apiKeyYes") : t("cveSettings.apiKeyNo")}</dd>
            </div>
            <div className="field-row">
              <dt>{t("cveSettings.msrcMonths")}</dt>
              <dd>{t("cveSettings.msrcMonthsValue", { n: st.msrc_months })}</dd>
            </div>
            <div className="field-row">
              <dt>{t("cveSettings.tracked")}</dt>
              <dd>{st.tracked_products}</dd>
            </div>
          </dl>
        )}
      </section>

      <section className="card">
        <div className="card-header">
          <h2>{t("cveSettings.rules")}</h2>
        </div>
        <div className="card-body stack">
          <p className="muted small">{t("cveSettings.rulesHelp")}</p>
          {canWrite && (
            <form className="form-grid" onSubmit={(e) => void addRule(e)}>
              {(
                [
                  ["name", "ruleName", "^ornek uygulama\\b"],
                  ["publisher", "rulePublisher", ""],
                  ["identifier", "ruleIdentifier", ""],
                  ["vendor", "ruleVendor", "ornek"],
                  ["product", "ruleProduct", "ornek_uygulama"],
                ] as const
              ).map(([k, label, ph]) => (
                <label key={k}>
                  {t(`cveSettings.${label}`)}
                  <input
                    className="input input-sm mono"
                    value={form[k]}
                    placeholder={ph}
                    required={k === "vendor" || k === "product"}
                    onChange={(e) => setForm({ ...form, [k]: e.target.value })}
                  />
                </label>
              ))}
              <button
                type="submit"
                className="btn btn-primary btn-sm"
                disabled={busy || (!form.name && !form.identifier)}
              >
                {t("cveSettings.addRule")}
              </button>
            </form>
          )}
        </div>
        <div className="table-wrap">
          <table className="table" aria-label={t("cveSettings.rules")}>
            <thead>
              <tr>
                <th>{t("cveSettings.ruleType")}</th>
                <th>{t("cveSettings.rulePattern")}</th>
                <th>{t("cveSettings.ruleCpe")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {[...custom, ...(showBuiltin ? builtin : [])].map((r) => (
                <tr key={r.id}>
                  <td>
                    <span className={`pill ${r.builtin ? "pill-muted" : "pill-info"}`}>
                      {r.builtin ? t("cveSettings.builtin") : t("cveSettings.custom")}
                    </span>
                  </td>
                  <td className="mono small cell-wrap">
                    {[
                      r.name,
                      r.identifier && `id: ${r.identifier}`,
                      r.publisher && `${t("cveSettings.publisherShort")}: ${r.publisher}`,
                      r.os && `os: ${r.os}`,
                    ]
                      .filter(Boolean)
                      .join("  ·  ")}
                  </td>
                  <td className="mono small">
                    cpe:2.3:{r.part || "a"}:{r.vendor}:{r.product}
                  </td>
                  <td>
                    {!r.builtin && canWrite && (
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        onClick={() => void deleteRule(r.id)}
                      >
                        {t("cveSettings.deleteRule")}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card-body">
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => setShowBuiltin((v) => !v)}>
            {showBuiltin
              ? t("cveSettings.hideBuiltin")
              : t("cveSettings.showBuiltin", { count: builtin.length })}
          </button>
        </div>
      </section>
    </div>
  );
}
