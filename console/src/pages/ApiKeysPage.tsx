import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, errorKey, type Role } from "../api/client";
import { useApi } from "../api/useApi";
import { CopyField } from "../components/CopyField";
import { formatDateTime, formatRelative } from "../format";
import { parseScope } from "../scope";

interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  role: Role;
  scope_ous: string[];
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
}

const ROLES: Role[] = ["readonly", "technician", "admin"];

export function ApiKeysPage() {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const [list, reload] = useApi<{ items: ApiKey[] }>("/api/v1/api-keys");
  const [f, setF] = useState({ name: "", role: "readonly" as Role, scope: "", days: 90 });
  const [created, setCreated] = useState<{ name: string; secret: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const r = await api<{ key: ApiKey; secret: string }>("/api/v1/api-keys", {
        method: "POST",
        body: { name: f.name, role: f.role, scope_ous: parseScope(f.scope), expires_in_days: f.days },
      });
      setCreated({ name: r.key.name, secret: r.secret });
      setF({ ...f, name: "", scope: "" });
      reload();
    } catch (err) {
      const invalid = err instanceof Error && "code" in err && err.code === "request.invalid";
      setError(invalid ? err.message : t(errorKey(err), { defaultValue: t("errors.unknown") }));
    }
  }

  async function revoke(k: ApiKey) {
    if (!window.confirm(t("apiKeys.confirmRevoke", { name: k.name }))) return;
    await api(`/api/v1/api-keys/${k.id}`, { method: "DELETE" }).catch(() => undefined);
    reload();
  }

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>{t("apiKeys.title")}</h1>
          <p className="muted">{t("apiKeys.subtitle")}</p>
        </div>
      </header>

      {created && (
        <section className="card card-body stack">
          <div className="alert alert-warning" role="status">
            {t("apiKeys.secretOnce", { name: created.name })}
          </div>
          <CopyField label={t("apiKeys.secret")} value={created.secret} />
          <CopyField
            label={t("apiKeys.example")}
            value={`curl -H "Authorization: Bearer ${created.secret}" https://<sunucu>:8443/api/v1/machines`}
          />
        </section>
      )}

      <section className="card">
        <form className="card-body stack" onSubmit={(e) => void submit(e)}>
          {error && (
            <div className="alert alert-danger" role="alert">
              {error}
            </div>
          )}
          <div className="form-grid">
            <label>
              {t("apiKeys.name")}
              <input
                className="input input-sm"
                required
                maxLength={100}
                placeholder={t("apiKeys.namePlaceholder")}
                value={f.name}
                onChange={(e) => setF({ ...f, name: e.target.value })}
              />
            </label>
            <label>
              {t("apiKeys.role")}
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
            <label>
              {t("apiKeys.days")}
              <input
                className="input input-sm"
                type="number"
                min={0}
                max={730}
                value={f.days}
                onChange={(e) => setF({ ...f, days: Number(e.target.value) })}
              />
              <span className="hint">{t("apiKeys.daysHint")}</span>
            </label>
            <label className="span-2">
              {t("apiKeys.scope")}
              <textarea
                className="textarea"
                rows={2}
                value={f.scope}
                onChange={(e) => setF({ ...f, scope: e.target.value })}
              />
            </label>
          </div>
          <p className="muted small">{t("apiKeys.note")}</p>
          <div>
            <button type="submit" className="btn btn-primary btn-sm">
              {t("apiKeys.create")}
            </button>
          </div>
        </form>
        <div className="table-wrap">
          <table className="table" aria-label={t("apiKeys.title")}>
            <thead>
              <tr>
                <th>{t("apiKeys.name")}</th>
                <th>{t("apiKeys.role")}</th>
                <th>{t("apiKeys.lastUsed")}</th>
                <th>{t("apiKeys.expires")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.status === "ok" && list.data.items.length === 0 && (
                <tr>
                  <td colSpan={5} className="muted">
                    {t("apiKeys.empty")}
                  </td>
                </tr>
              )}
              {list.status === "ok" &&
                list.data.items.map((k) => (
                  <tr key={k.id}>
                    <td>
                      <strong>{k.name}</strong>
                      <span className="mono small muted block">{k.key_prefix}…</span>
                    </td>
                    <td>
                      {t(`roles.${k.role}`)}
                      {k.scope_ous.length > 0 && (
                        <span className="muted small block">{k.scope_ous.join("; ")}</span>
                      )}
                    </td>
                    <td>{formatRelative(k.last_used_at, lng, t("common.never"))}</td>
                    <td>{formatDateTime(k.expires_at, lng, t("apiKeys.noExpiry"))}</td>
                    <td>
                      {k.revoked_at ? (
                        <span className="pill pill-danger">{t("apiKeys.revoked")}</span>
                      ) : (
                        <button type="button" className="btn btn-ghost btn-sm" onClick={() => void revoke(k)}>
                          {t("apiKeys.revoke")}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
