import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, errorKey, type RateProfile, type TransferSettings } from "../api/client";
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
            <label>
              {t("transfer.total")}
              <input
                className="input input-sm"
                type="number"
                min={0}
                max={100000000}
                value={form.total_kbps ?? 0}
                onChange={num("total_kbps")}
              />
              <span className="hint">{t("transfer.totalHint")}</span>
            </label>
          </div>
          <ProfilesEditor
            profiles={form.profiles ?? []}
            onChange={(profiles) => setForm({ ...form, profiles })}
          />
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

const DAYS = [1, 2, 3, 4, 5, 6, 0];
const hhmm = (m: number) =>
  `${String(Math.floor(m / 60)).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;
const toMinutes = (v: string) => {
  const [h = 0, m = 0] = v.split(":").map(Number);
  return h * 60 + m;
};

// ProfilesEditor, saat bazlı istemci hız sınırlarını düzenler (ör. mesai saatinde 2 Mbps).
function ProfilesEditor({
  profiles,
  onChange,
}: {
  profiles: RateProfile[];
  onChange: (p: RateProfile[]) => void;
}) {
  const { t } = useTranslation();
  const set = (i: number, patch: Partial<RateProfile>) =>
    onChange(profiles.map((p, j) => (j === i ? { ...p, ...patch } : p)));
  return (
    <div className="stack">
      <p className="small strong">{t("transfer.profiles")}</p>
      <p className="hint">{t("transfer.profilesHint")}</p>
      {profiles.map((p, i) => (
        <div key={i} className="card card-body stack">
          <div className="report-actions rule-row">
            <input
              className="input input-sm"
              aria-label={t("transfer.profileName")}
              placeholder={t("transfer.profileName")}
              value={p.name}
              onChange={(e) => set(i, { name: e.target.value })}
            />
            <input
              className="input input-sm"
              type="time"
              aria-label={t("transfer.from")}
              value={hhmm(p.start_minute)}
              onChange={(e) => set(i, { start_minute: toMinutes(e.target.value) })}
            />
            <input
              className="input input-sm"
              type="time"
              aria-label={t("transfer.to")}
              value={hhmm(p.end_minute)}
              onChange={(e) => set(i, { end_minute: toMinutes(e.target.value) })}
            />
            <input
              className="input input-sm"
              type="number"
              min={64}
              aria-label={t("transfer.profileKbps")}
              value={p.kbps}
              onChange={(e) => set(i, { kbps: Number(e.target.value) })}
            />
            <span className="muted small">kbps</span>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              aria-label={t("transfer.removeProfile")}
              onClick={() => onChange(profiles.filter((_, j) => j !== i))}
            >
              ×
            </button>
          </div>
          <fieldset className="day-picker">
            {DAYS.map((d) => (
              <label key={d} className="check">
                <input
                  type="checkbox"
                  className="checkbox"
                  checked={p.weekdays.includes(d)}
                  onChange={() =>
                    set(i, {
                      weekdays: p.weekdays.includes(d)
                        ? p.weekdays.filter((x) => x !== d)
                        : [...p.weekdays, d],
                    })
                  }
                />
                <span>{t(`windows.dayShort.${d}`)}</span>
              </label>
            ))}
          </fieldset>
        </div>
      ))}
      {profiles.length < 10 && (
        <div>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() =>
              onChange([
                ...profiles,
                {
                  name: t("transfer.workHours"),
                  weekdays: [1, 2, 3, 4, 5],
                  start_minute: 540,
                  end_minute: 1080,
                  kbps: 2000,
                },
              ])
            }
          >
            {t("transfer.addProfile")}
          </button>
        </div>
      )}
    </div>
  );
}
