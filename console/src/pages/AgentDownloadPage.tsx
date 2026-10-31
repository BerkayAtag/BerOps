import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, errorKey } from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";
import { CopyField } from "../components/CopyField";
import { formatDateTime } from "../format";

interface ServerInfo {
  version: string;
  agent_url: string;
  ca_fingerprint: string;
}

interface RegKey {
  id: string;
  name: string;
  key_prefix: string;
  require_approval: boolean;
  max_uses: number | null;
  use_count: number;
  expires_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

interface CreatedKey {
  key: RegKey;
  secret: string;
  install: { windows: string; macos: string };
}

const RELEASES = "https://github.com/BerkayAtag/automation-ber/releases/latest";

function NewKeyForm({ onCreated }: { onCreated: (k: CreatedKey) => void }) {
  const { t } = useTranslation();
  const [f, setF] = useState({ name: "", approval: false, maxUses: "", hours: "" });
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const k = await api<CreatedKey>("/api/v1/registration-keys", {
        method: "POST",
        body: {
          name: f.name,
          require_approval: f.approval,
          max_uses: f.maxUses ? Number(f.maxUses) : null,
          expires_in_hours: f.hours ? Number(f.hours) : null,
        },
      });
      onCreated(k);
      setF({ name: "", approval: false, maxUses: "", hours: "" });
    } catch (err) {
      const invalid = err instanceof Error && "code" in err && err.code === "request.invalid";
      setError(invalid ? err.message : t(errorKey(err), { defaultValue: t("errors.unknown") }));
    }
  }

  return (
    <form className="card-body stack" onSubmit={(e) => void submit(e)}>
      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}
      <div className="form-grid">
        <label>
          {t("agentDownload.field.name")}
          <input
            className="input input-sm"
            required
            maxLength={100}
            placeholder={t("agentDownload.field.namePlaceholder")}
            value={f.name}
            onChange={(e) => setF({ ...f, name: e.target.value })}
          />
        </label>
        <label>
          {t("agentDownload.field.maxUses")}
          <input
            className="input input-sm"
            type="number"
            min={1}
            placeholder="∞"
            value={f.maxUses}
            onChange={(e) => setF({ ...f, maxUses: e.target.value })}
          />
        </label>
        <label>
          {t("agentDownload.field.hours")}
          <input
            className="input input-sm"
            type="number"
            min={1}
            max={8760}
            placeholder="∞"
            value={f.hours}
            onChange={(e) => setF({ ...f, hours: e.target.value })}
          />
        </label>
      </div>
      <label className="check">
        <input
          type="checkbox"
          className="checkbox"
          checked={f.approval}
          onChange={(e) => setF({ ...f, approval: e.target.checked })}
        />
        <span>{t("agentDownload.field.approval")}</span>
      </label>
      <div>
        <button type="submit" className="btn btn-primary btn-sm">
          {t("agentDownload.create")}
        </button>
      </div>
    </form>
  );
}

export function AgentDownloadPage() {
  const { t, i18n } = useTranslation();
  const { can } = useAuth();
  const manage = can("regkeys.manage");
  const [info] = useApi<ServerInfo>("/api/v1/server-info");
  const [keys, reload] = useApi<{ items: RegKey[] }>(manage ? "/api/v1/registration-keys" : null);
  const [created, setCreated] = useState<CreatedKey | null>(null);

  async function revoke(k: RegKey) {
    if (!window.confirm(t("agentDownload.confirmRevoke", { name: k.name }))) return;
    await api(`/api/v1/registration-keys/${k.id}`, { method: "DELETE" }).catch(() => undefined);
    reload();
  }

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>{t("agentDownload.title")}</h1>
          <p className="muted">{t("agentDownload.subtitle")}</p>
        </div>
      </header>

      <section className="card card-body stack">
        <h2>{t("agentDownload.packages")}</h2>
        <p className="muted small">{t("agentDownload.packagesHint")}</p>
        <div className="report-actions">
          <a className="btn btn-primary btn-sm" href={RELEASES} target="_blank" rel="noreferrer">
            {t("agentDownload.windows")}
          </a>
          <a className="btn btn-primary btn-sm" href={RELEASES} target="_blank" rel="noreferrer">
            {t("agentDownload.macos")}
          </a>
        </div>
        {info.status === "ok" && (
          <div className="form-grid">
            <CopyField label={t("agentDownload.serverUrl")} value={info.data.agent_url} />
            <CopyField label={t("agentDownload.caHash")} value={info.data.ca_fingerprint} />
          </div>
        )}
      </section>

      {created && (
        <section className="card card-body stack">
          <h2>{t("agentDownload.createdTitle", { name: created.key.name })}</h2>
          <div className="alert alert-warning" role="status">
            {t("agentDownload.secretOnce")}
          </div>
          <CopyField label={t("agentDownload.secret")} value={created.secret} />
          <CopyField label={t("agentDownload.cmdWindows")} value={created.install.windows} />
          <CopyField label={t("agentDownload.cmdMacos")} value={created.install.macos} />
          <p className="muted small">{t("agentDownload.gpoHint")}</p>
        </section>
      )}

      {manage ? (
        <section className="card">
          <div className="card-header">
            <h2>{t("agentDownload.keys")}</h2>
          </div>
          <NewKeyForm onCreated={(k) => (setCreated(k), reload())} />
          <div className="table-wrap">
            <table className="table" aria-label={t("agentDownload.keys")}>
              <thead>
                <tr>
                  <th>{t("agentDownload.field.name")}</th>
                  <th>{t("agentDownload.col.prefix")}</th>
                  <th>{t("agentDownload.col.uses")}</th>
                  <th>{t("agentDownload.col.expires")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {keys.status === "ok" && keys.data.items.length === 0 && (
                  <tr>
                    <td colSpan={5} className="muted">
                      {t("agentDownload.empty")}
                    </td>
                  </tr>
                )}
                {keys.status === "ok" &&
                  keys.data.items.map((k) => (
                    <tr key={k.id}>
                      <td>
                        <strong>{k.name}</strong>
                        {k.require_approval && <span className="tag">{t("agentDownload.approvalTag")}</span>}
                      </td>
                      <td className="mono small">{k.key_prefix}…</td>
                      <td>
                        {k.use_count}
                        {k.max_uses !== null && ` / ${k.max_uses}`}
                      </td>
                      <td>{formatDateTime(k.expires_at, i18n.language, t("agentDownload.noExpiry"))}</td>
                      <td>
                        {k.revoked_at ? (
                          <span className="pill pill-danger">{t("agentDownload.revoked")}</span>
                        ) : (
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            onClick={() => void revoke(k)}
                          >
                            {t("agentDownload.revoke")}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : (
        <div className="alert alert-info">{t("agentDownload.noPermission")}</div>
      )}
    </div>
  );
}
