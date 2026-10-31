import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { Link } from "react-router";
import {
  api,
  errorKey,
  type ADComputer,
  type ADMapping,
  type ADSettings,
  type ADTestResult,
  type Role,
} from "../api/client";
import { useApi } from "../api/useApi";
import { formatRelative } from "../format";
import { parseScope } from "../scope";

const ROLES: Role[] = ["admin", "technician", "readonly"];

function errText(t: TFunction, err: unknown) {
  const invalid = err instanceof Error && "code" in err && err.code === "request.invalid";
  return invalid ? err.message : t(errorKey(err), { defaultValue: t("errors.unknown") });
}

function ConnectionForm({ initial, onSaved }: { initial: ADSettings; onSaved: () => void }) {
  const { t } = useTranslation();
  const [f, setF] = useState({ ...initial, bind_password: "" });
  const [notice, setNotice] = useState<{ kind: "info" | "danger"; text: string } | null>(null);
  const [test, setTest] = useState({ username: "", password: "" });
  const [result, setResult] = useState<ADTestResult | null>(null);
  const [busy, setBusy] = useState(false);
  const text = (k: keyof typeof f) => (e: { target: { value: string } }) =>
    setF({ ...f, [k]: e.target.value });

  async function save(e: FormEvent) {
    e.preventDefault();
    setNotice(null);
    try {
      await api("/api/v1/settings/ad", { method: "PUT", body: f });
      setF({ ...f, bind_password: "" });
      setNotice({ kind: "info", text: t("common.saved") });
      onSaved();
    } catch (err) {
      setNotice({ kind: "danger", text: errText(t, err) });
    }
  }

  async function runTest(withUser: boolean) {
    setBusy(true);
    setResult(null);
    try {
      setResult(
        await api<ADTestResult>("/api/v1/settings/ad/test", { method: "POST", body: withUser ? test : {} }),
      );
    } catch (err) {
      setResult({ ok: false, message: errText(t, err) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card-body stack" onSubmit={(e) => void save(e)}>
      {notice && (
        <div className={`alert alert-${notice.kind}`} role="status">
          {notice.text}
        </div>
      )}
      <label className="filter-check">
        <input
          type="checkbox"
          className="checkbox"
          checked={f.enabled}
          onChange={(e) => setF({ ...f, enabled: e.target.checked })}
        />
        {t("adSettings.enabled")}
      </label>
      <div className="form-grid">
        <label>
          {t("adSettings.url")}
          <input
            className="input input-sm mono"
            placeholder="ldaps://dc01.corp.example"
            value={f.url}
            onChange={text("url")}
          />
          <span className="hint">{t("adSettings.urlHint")}</span>
        </label>
        <label>
          {t("adSettings.baseDn")}
          <input
            className="input input-sm mono"
            placeholder="DC=corp,DC=example"
            value={f.base_dn}
            onChange={text("base_dn")}
          />
        </label>
        <label>
          {t("adSettings.bindDn")}
          <input className="input input-sm mono" value={f.bind_dn} onChange={text("bind_dn")} />
        </label>
        <label>
          {t("adSettings.bindPassword")}
          <input
            className="input input-sm"
            type="password"
            autoComplete="new-password"
            placeholder={initial.has_password ? t("adSettings.passwordSet") : ""}
            value={f.bind_password}
            onChange={text("bind_password")}
          />
          <span className="hint">{t("adSettings.passwordHint")}</span>
        </label>
        <label>
          {t("adSettings.userAttr")}
          <select className="select select-sm" value={f.user_attr} onChange={text("user_attr")}>
            <option value="sAMAccountName">sAMAccountName</option>
            <option value="userPrincipalName">userPrincipalName</option>
          </select>
        </label>
        <label>
          {t("adSettings.timeout")}
          <input
            className="input input-sm"
            type="number"
            min={2}
            max={60}
            value={f.timeout_seconds}
            onChange={(e) => setF({ ...f, timeout_seconds: Number(e.target.value) })}
          />
        </label>
        <label className="span-2">
          {t("adSettings.userFilter")}
          <input className="input input-sm mono" value={f.user_filter} onChange={text("user_filter")} />
        </label>
        <label className="span-2">
          {t("adSettings.computersDn")}
          <input
            className="input input-sm mono"
            value={f.computers_base_dn}
            onChange={text("computers_base_dn")}
          />
        </label>
      </div>
      <label>
        {t("adSettings.caCert")}
        <textarea
          className="textarea"
          rows={4}
          placeholder="-----BEGIN CERTIFICATE-----"
          value={f.ca_cert_pem}
          onChange={text("ca_cert_pem")}
        />
        <span className="hint">{t("adSettings.caHint")}</span>
      </label>
      <div className="report-actions">
        <button type="submit" className="btn btn-primary btn-sm">
          {t("common.save")}
        </button>
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          disabled={busy}
          onClick={() => void runTest(false)}
        >
          {t("adSettings.test")}
        </button>
      </div>
      <div className="form-grid">
        <label>
          {t("adSettings.testUsername")}
          <input
            className="input input-sm"
            autoComplete="off"
            value={test.username}
            onChange={(e) => setTest({ ...test, username: e.target.value })}
          />
        </label>
        <label>
          {t("adSettings.testPassword")}
          <input
            className="input input-sm"
            type="password"
            autoComplete="off"
            value={test.password}
            onChange={(e) => setTest({ ...test, password: e.target.value })}
          />
        </label>
        <div>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            disabled={busy || !test.username || !test.password}
            onClick={() => void runTest(true)}
          >
            {t("adSettings.testUser")}
          </button>
        </div>
      </div>
      {result && (
        <div className={`alert ${result.ok ? "alert-info" : "alert-danger"}`} role="status">
          <p className="strong">{result.message}</p>
          {result.role && (
            <p className="small">
              {t("adSettings.resolvedRole")}: {t(`roles.${result.role}`)}
              {result.scope_ous && result.scope_ous.length > 0 && ` · ${result.scope_ous.join("; ")}`}
            </p>
          )}
          {result.user && (
            <details>
              <summary className="small">
                {t("adSettings.groups", { count: result.user.groups.length })}
              </summary>
              <ul className="ref-list small mono">
                {result.user.groups.map((g) => (
                  <li key={g}>{g}</li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}
    </form>
  );
}

function Mappings() {
  const { t } = useTranslation();
  const [list, reload] = useApi<{ items: ADMapping[] }>("/api/v1/settings/ad/mappings");
  const [f, setF] = useState({ group_dn: "", role: "technician" as Role, scope: "" });
  const [error, setError] = useState<string | null>(null);

  async function add(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api("/api/v1/settings/ad/mappings", {
        method: "POST",
        body: { group_dn: f.group_dn, role: f.role, scope_ous: parseScope(f.scope) },
      });
      setF({ group_dn: "", role: f.role, scope: "" });
      reload();
    } catch (err) {
      setError(errText(t, err));
    }
  }

  async function remove(id: string) {
    try {
      await api(`/api/v1/settings/ad/mappings/${id}`, { method: "DELETE" });
      reload();
    } catch (err) {
      setError(errText(t, err));
    }
  }

  const items = list.status === "ok" ? list.data.items : [];
  return (
    <section className="card">
      <div className="card-header">
        <h2>{t("adSettings.mappings")}</h2>
      </div>
      <div className="card-body stack">
        <p className="muted small">{t("adSettings.mappingsHint")}</p>
        {error && (
          <div className="alert alert-danger" role="alert">
            {error}
          </div>
        )}
        <form className="form-grid" onSubmit={(e) => void add(e)}>
          <label className="span-2">
            {t("adSettings.groupDn")}
            <input
              className="input input-sm mono"
              required
              placeholder="CN=BerOps-Teknisyen,OU=Gruplar,DC=corp,DC=example"
              value={f.group_dn}
              onChange={(e) => setF({ ...f, group_dn: e.target.value })}
            />
          </label>
          <label>
            {t("users.field.role")}
            <select
              className="select select-sm"
              value={f.role}
              onChange={(e) => setF({ ...f, role: e.target.value as Role })}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {t(`roles.${r}`)}
                </option>
              ))}
            </select>
          </label>
          {f.role !== "admin" && (
            <label className="span-2">
              {t("users.field.scope")}
              <textarea
                className="textarea"
                rows={2}
                value={f.scope}
                onChange={(e) => setF({ ...f, scope: e.target.value })}
              />
            </label>
          )}
          <div>
            <button type="submit" className="btn btn-primary btn-sm">
              {t("adSettings.addMapping")}
            </button>
          </div>
        </form>
      </div>
      {items.length === 0 ? (
        <p className="card-body muted small">{t("adSettings.noMappings")}</p>
      ) : (
        <ul className="list-rows">
          {items.map((m) => (
            <li key={m.id}>
              <span className={`role-badge role-${m.role}`}>{t(`roles.${m.role}`)}</span>
              <span className="grow two-line">
                <span className="mono small">{m.group_dn}</span>
                <span className="muted small">
                  {m.scope_ous.length ? m.scope_ous.join("; ") : t("users.allMachines")}
                </span>
              </span>
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => void remove(m.id)}>
                {t("cveSettings.deleteRule")}
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Computers() {
  const { t, i18n } = useTranslation();
  const [items, setItems] = useState<ADComputer[] | null>(null);
  const [onlyMissing, setOnlyMissing] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function load() {
    setBusy(true);
    setError(null);
    try {
      setItems((await api<{ items: ADComputer[] }>("/api/v1/ad/computers")).items);
    } catch (err) {
      setError(errText(t, err));
    } finally {
      setBusy(false);
    }
  }
  const shown = (items ?? []).filter((c) => !onlyMissing || !c.machine_id);
  return (
    <section className="card">
      <div className="card-header card-header-row">
        <h2>{t("adSettings.computers")}</h2>
        <button type="button" className="btn btn-ghost btn-sm" disabled={busy} onClick={() => void load()}>
          {t("adSettings.loadComputers")}
        </button>
      </div>
      <div className="card-body stack">
        <p className="muted small">{t("adSettings.computersHint")}</p>
        {error && (
          <div className="alert alert-danger" role="alert">
            {error}
          </div>
        )}
        {items && (
          <label className="filter-check">
            <input
              type="checkbox"
              className="checkbox"
              checked={onlyMissing}
              onChange={(e) => setOnlyMissing(e.target.checked)}
            />
            {t("adSettings.onlyMissing")} ({items.filter((c) => !c.machine_id).length} / {items.length})
          </label>
        )}
      </div>
      {items && (
        <div className="table-wrap">
          <table className="table" aria-label={t("adSettings.computers")}>
            <thead>
              <tr>
                <th>{t("adSettings.computerCol.name")}</th>
                <th>{t("adSettings.computerCol.os")}</th>
                <th>{t("adSettings.computerCol.ou")}</th>
                <th>{t("adSettings.computerCol.lastLogon")}</th>
                <th>{t("adSettings.computerCol.agent")}</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((c) => (
                <tr key={c.dn}>
                  <td className="strong">{c.name}</td>
                  <td>{c.operating_system}</td>
                  <td className="small cell-wrap">{c.ou}</td>
                  <td>{formatRelative(c.last_logon, i18n.language, t("common.never"))}</td>
                  <td>
                    {c.machine_id ? (
                      <Link to={`/makineler/${c.machine_id}`} className="pill pill-success">
                        {t("adSettings.agentInstalled")}
                      </Link>
                    ) : (
                      <span className="pill pill-warning">{t("adSettings.noAgent")}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export function AdSettingsPage() {
  const { t } = useTranslation();
  const [settings, reload] = useApi<ADSettings>("/api/v1/settings/ad");
  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>{t("adSettings.title")}</h1>
          <p className="muted">{t("adSettings.subtitle")}</p>
        </div>
      </header>
      {settings.status === "error" && (
        <div className="alert alert-danger" role="alert">
          {t(settings.error, { defaultValue: t("errors.unknown") })}
        </div>
      )}
      <section className="card">
        <div className="card-header">
          <h2>{t("adSettings.connection")}</h2>
        </div>
        {settings.status === "ok" && <ConnectionForm initial={settings.data} onSaved={reload} />}
      </section>
      <Mappings />
      {settings.status === "ok" && settings.data.enabled && <Computers />}
    </div>
  );
}
