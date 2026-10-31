import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, errorKey } from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";

interface RemoteSettings {
  enabled: boolean;
  session_minutes: number;
}

export function RemoteSettingsPage() {
  const { t } = useTranslation();
  const { can } = useAuth();
  const [resp] = useApi<RemoteSettings>("/api/v1/settings/remote");
  const [edits, setForm] = useState<RemoteSettings | null>(null);
  const form = edits ?? (resp.status === "ok" ? resp.data : null);
  const [notice, setNotice] = useState<{ kind: "info" | "danger"; text: string } | null>(null);
  if (!form) return <p className="muted">{t("common.loading")}</p>;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setNotice(null);
    try {
      await api("/api/v1/settings/remote", { method: "PUT", body: form });
      setNotice({ kind: "info", text: t("common.saved") });
    } catch (err) {
      setNotice({ kind: "danger", text: t(errorKey(err), { defaultValue: t("errors.unknown") }) });
    }
  }

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>{t("remoteSettings.title")}</h1>
          <p className="muted">{t("remoteSettings.subtitle")}</p>
        </div>
      </header>
      {notice && (
        <div className={`alert alert-${notice.kind}`} role="status">
          {notice.text}
        </div>
      )}
      <form className="card" onSubmit={(e) => void onSubmit(e)}>
        <fieldset className="card-body stack" disabled={!can("remote.settings")}>
          <label className="filter-check">
            <input
              type="checkbox"
              className="checkbox"
              checked={form.enabled}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
            />
            {t("remoteSettings.enabled")}
          </label>
          <label className="field-inline">
            {t("remoteSettings.session")}
            <input
              className="input input-sm"
              type="number"
              min={1}
              max={120}
              value={form.session_minutes}
              onChange={(e) => setForm({ ...form, session_minutes: Number(e.target.value) })}
            />
            <span className="hint">{t("remoteSettings.sessionHint")}</span>
          </label>
          <p className="muted small">{t("remoteSettings.perMachine")}</p>
          <div>
            <button type="submit" className="btn btn-primary">
              {t("common.save")}
            </button>
          </div>
        </fieldset>
      </form>
    </div>
  );
}
