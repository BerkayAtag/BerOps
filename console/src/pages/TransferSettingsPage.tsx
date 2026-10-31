import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, errorKey, type TransferSettings } from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";

export function TransferSettingsPage() {
  const { t } = useTranslation();
  const { can } = useAuth();
  const [resp] = useApi<TransferSettings>("/api/v1/settings/transfer");
  const [edits, setForm] = useState<TransferSettings | null>(null);
  const form = edits ?? (resp.status === "ok" ? resp.data : null);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<{ kind: "info" | "danger"; text: string } | null>(null);
  const editable = can("transfer.limits.manage");

  if (!form) {
    return resp.status === "error" ? (
      <div className="alert alert-danger" role="alert">
        {t(resp.error, { defaultValue: t("errors.unknown") })}
      </div>
    ) : (
      <p className="muted">{t("common.loading")}</p>
    );
  }

  const num = (k: keyof TransferSettings) => (e: { target: { value: string } }) =>
    setForm({ ...form, [k]: Number(e.target.value) });

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    setNotice(null);
    try {
      await api("/api/v1/settings/transfer", { method: "PUT", body: form });
      setNotice({ kind: "info", text: t("common.saved") });
    } catch (err) {
      setNotice({ kind: "danger", text: t(errorKey(err), { defaultValue: t("errors.unknown") }) });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>{t("transfer.title")}</h1>
          <p className="muted">{t("transfer.subtitle")}</p>
        </div>
      </header>
      {notice && (
        <div className={`alert alert-${notice.kind}`} role="status">
          {notice.text}
        </div>
      )}
      <form className="card" onSubmit={(e) => void onSubmit(e)}>
        <fieldset className="card-body stack" disabled={!editable}>
          <div className="form-grid">
            <label>
              {t("transfer.perClient")}
              <input
                className="input input-sm"
                type="number"
                min={64}
                max={10000000}
                value={form.per_client_kbps}
                onChange={num("per_client_kbps")}
              />
              <span className="hint">{t("transfer.perClientHint")}</span>
            </label>
            <label>
              {t("transfer.maxUpload")}
              <input
                className="input input-sm"
                type="number"
                min={1}
                max={102400}
                value={form.max_upload_mb}
                onChange={num("max_upload_mb")}
              />
            </label>
            <label>
              {t("transfer.expiry")}
              <input
                className="input input-sm"
                type="number"
                min={1}
                max={720}
                value={form.default_expiry_hours}
                onChange={num("default_expiry_hours")}
              />
            </label>
          </div>
          <label className="filter-check">
            <input
              type="checkbox"
              className="checkbox"
              checked={form.command_approval}
              onChange={(e) => setForm({ ...form, command_approval: e.target.checked })}
            />
            {t("transfer.approval")}
          </label>
          <p className="hint">{t("transfer.approvalHint")}</p>
          <div>
            <button type="submit" className="btn btn-primary" disabled={!editable || saving}>
              {saving ? t("common.saving") : t("common.save")}
            </button>
          </div>
        </fieldset>
      </form>
    </div>
  );
}
