import { useState, type ChangeEvent, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, errorKey, type AgentSettings, type AgentSettingsResponse } from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";
import { formatBytes, formatDateTime } from "../format";

export function AgentSettingsPage() {
  const { t, i18n } = useTranslation();
  const { can } = useAuth();
  const [resp] = useApi<AgentSettingsResponse>("/api/v1/settings/agent");
  // Kullanıcı düzenleyene kadar sunucudaki değerler gösterilir.
  const [edits, setForm] = useState<AgentSettings | null>(null);
  const form = edits ?? (resp.status === "ok" ? resp.data.settings : null);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<{ kind: "info" | "danger"; text: string } | null>(null);
  const editable = can("settings.write");

  if (resp.status === "loading" || !form) {
    return resp.status === "error" ? (
      <div className="alert alert-danger" role="alert">
        {t(resp.error, { defaultValue: t("errors.unknown") })}
      </div>
    ) : (
      <p className="muted">{t("common.loading")}</p>
    );
  }

  const cab = resp.status === "ok" ? resp.data.wsus_cab : null;
  const valid =
    form.full_scan_interval_hours >= 1 &&
    form.full_scan_interval_hours <= 168 &&
    form.delta_scan_interval_hours >= 1 &&
    form.delta_scan_interval_hours <= form.full_scan_interval_hours &&
    form.scan_cpu_limit_percent >= 1 &&
    form.scan_cpu_limit_percent <= 100;

  const setNum = (k: keyof AgentSettings) => (e: ChangeEvent<HTMLInputElement>) =>
    setForm({ ...form, [k]: Number(e.target.value) });

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!form) return;
    setSaving(true);
    setNotice(null);
    try {
      await api("/api/v1/settings/agent", { method: "PUT", body: form });
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
          <h1>{t("settings.agentTitle")}</h1>
          <p className="muted">{t("settings.agentSubtitle")}</p>
        </div>
      </header>
      {!editable && <div className="alert alert-info">{t("settings.readOnly")}</div>}

      <form className="card card-body settings-form" onSubmit={(e) => void onSubmit(e)}>
        <fieldset disabled={!editable || saving}>
          <div className="form-grid">
            <label className="field">
              <span>{t("settings.fullInterval")}</span>
              <input
                className="input"
                type="number"
                min={1}
                max={168}
                value={form.full_scan_interval_hours}
                onChange={setNum("full_scan_interval_hours")}
              />
              <small className="muted">{t("settings.fullIntervalHelp")}</small>
            </label>
            <label className="field">
              <span>{t("settings.deltaInterval")}</span>
              <input
                className="input"
                type="number"
                min={1}
                max={form.full_scan_interval_hours}
                value={form.delta_scan_interval_hours}
                onChange={setNum("delta_scan_interval_hours")}
              />
              <small className="muted">{t("settings.deltaIntervalHelp")}</small>
            </label>
            <label className="field">
              <span>{t("settings.cpuLimit")}</span>
              <input
                className="input"
                type="number"
                min={1}
                max={100}
                value={form.scan_cpu_limit_percent}
                onChange={setNum("scan_cpu_limit_percent")}
              />
              <small className="muted">{t("settings.cpuLimitHelp")}</small>
            </label>
          </div>

          <label className="check">
            <input
              type="checkbox"
              className="checkbox"
              checked={form.defer_on_battery}
              onChange={(e) => setForm({ ...form, defer_on_battery: e.target.checked })}
            />
            <span>{t("settings.deferBattery")}</span>
          </label>
          <label className="check">
            <input
              type="checkbox"
              className="checkbox"
              checked={form.defer_when_user_active}
              onChange={(e) => setForm({ ...form, defer_when_user_active: e.target.checked })}
            />
            <span>
              {t("settings.deferActive")}
              <small className="muted block">{t("settings.deferActiveHelp")}</small>
            </span>
          </label>

          <div className="field radio-group" role="radiogroup" aria-label={t("settings.wuSource")}>
            <span>{t("settings.wuSource")}</span>
            {(["online", "offline"] as const).map((v) => (
              <label key={v} className="check">
                <input
                  type="radio"
                  name="wu"
                  checked={form.windows_update_source === v}
                  onChange={() => setForm({ ...form, windows_update_source: v })}
                />
                <span>{t(v === "online" ? "settings.wuOnline" : "settings.wuOffline")}</span>
              </label>
            ))}
            <small
              className={`muted${!cab && form.windows_update_source === "offline" ? " text-warning" : ""}`}
            >
              {cab
                ? t("settings.cabPresent", {
                    size: formatBytes(cab.size_bytes, i18n.language),
                    date: formatDateTime(cab.modified_at, i18n.language),
                  })
                : t("settings.cabMissing")}
            </small>
          </div>
        </fieldset>

        {!valid && <div className="alert alert-danger">{t("settings.invalid")}</div>}
        {notice && (
          <div className={`alert alert-${notice.kind}`} role="status">
            {notice.text}
          </div>
        )}
        <div className="form-actions">
          <button
            type="submit"
            className="btn btn-primary"
            disabled={!editable || saving || !valid}
            title={editable ? undefined : t("common.noPermission")}
          >
            {saving ? t("common.saving") : t("common.save")}
          </button>
        </div>
      </form>
    </div>
  );
}
