import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, errorKey } from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";
import { parseScope } from "../scope";

interface MaintenanceWindow {
  id: string;
  name: string;
  weekdays: number[];
  start_minute: number;
  duration_minutes: number;
  timezone: string;
  scope_ous: string[];
  enabled: boolean;
  open_now?: boolean;
}

// Pazartesiden başlayarak gösterilir; değerler Go time.Weekday ile aynıdır (0 = Pazar).
const DAYS = [1, 2, 3, 4, 5, 6, 0];

const hhmm = (m: number) =>
  `${String(Math.floor(m / 60)).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;

const empty = {
  name: "",
  weekdays: [6] as number[],
  start: "22:00",
  hours: 4,
  timezone: "Europe/Istanbul",
  scope: "",
  enabled: true,
};

function WindowForm({ initial, onDone }: { initial?: MaintenanceWindow; onDone: () => void }) {
  const { t } = useTranslation();
  const [f, setF] = useState(
    initial
      ? {
          name: initial.name,
          weekdays: initial.weekdays,
          start: hhmm(initial.start_minute),
          hours: initial.duration_minutes / 60,
          timezone: initial.timezone,
          scope: initial.scope_ous.join("\n"),
          enabled: initial.enabled,
        }
      : empty,
  );
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const [h = 0, m = 0] = f.start.split(":").map(Number);
    const body = {
      name: f.name,
      weekdays: f.weekdays,
      start_minute: h * 60 + m,
      duration_minutes: Math.round(f.hours * 60),
      timezone: f.timezone,
      scope_ous: parseScope(f.scope),
      enabled: f.enabled,
    };
    try {
      await api(initial ? `/api/v1/maintenance-windows/${initial.id}` : "/api/v1/maintenance-windows", {
        method: initial ? "PUT" : "POST",
        body,
      });
      onDone();
    } catch (err) {
      const invalid = err instanceof Error && "code" in err && err.code === "request.invalid";
      setError(invalid ? err.message : t(errorKey(err), { defaultValue: t("errors.unknown") }));
    }
  }

  const toggleDay = (d: number) =>
    setF({ ...f, weekdays: f.weekdays.includes(d) ? f.weekdays.filter((x) => x !== d) : [...f.weekdays, d] });

  return (
    <form className="card-body stack" onSubmit={(e) => void submit(e)}>
      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}
      <div className="form-grid">
        <label>
          {t("windows.field.name")}
          <input
            className="input input-sm"
            required
            value={f.name}
            onChange={(e) => setF({ ...f, name: e.target.value })}
          />
        </label>
        <label>
          {t("windows.field.start")}
          <input
            className="input input-sm"
            type="time"
            required
            value={f.start}
            onChange={(e) => setF({ ...f, start: e.target.value })}
          />
        </label>
        <label>
          {t("windows.field.hours")}
          <input
            className="input input-sm"
            type="number"
            min={0.25}
            max={24}
            step={0.25}
            value={f.hours}
            onChange={(e) => setF({ ...f, hours: Number(e.target.value) })}
          />
        </label>
        <label>
          {t("windows.field.timezone")}
          <input
            className="input input-sm"
            value={f.timezone}
            onChange={(e) => setF({ ...f, timezone: e.target.value })}
          />
        </label>
      </div>
      <fieldset className="day-picker">
        <legend>{t("windows.field.days")}</legend>
        {DAYS.map((d) => (
          <label key={d} className="check">
            <input
              type="checkbox"
              className="checkbox"
              checked={f.weekdays.includes(d)}
              onChange={() => toggleDay(d)}
            />
            <span>{t(`windows.day.${d}`)}</span>
          </label>
        ))}
      </fieldset>
      <label>
        {t("windows.field.scope")}
        <textarea
          className="textarea"
          rows={2}
          placeholder="OU=Sunucular,DC=ornek,DC=local"
          value={f.scope}
          onChange={(e) => setF({ ...f, scope: e.target.value })}
        />
        <small className="muted">{t("windows.scopeHint")}</small>
      </label>
      <label className="check">
        <input
          type="checkbox"
          className="checkbox"
          checked={f.enabled}
          onChange={(e) => setF({ ...f, enabled: e.target.checked })}
        />
        <span>{t("windows.field.enabled")}</span>
      </label>
      <div>
        <button type="submit" className="btn btn-primary btn-sm" disabled={f.weekdays.length === 0}>
          {t("common.save")}
        </button>
      </div>
    </form>
  );
}

export function MaintenanceWindowsPage() {
  const { t } = useTranslation();
  const { can } = useAuth();
  const [list, reload] = useApi<{ items: MaintenanceWindow[] }>("/api/v1/maintenance-windows");
  const [editing, setEditing] = useState<string | null>(null);
  const editable = can("settings.write");

  async function remove(w: MaintenanceWindow) {
    if (!window.confirm(t("windows.confirmDelete", { name: w.name }))) return;
    await api(`/api/v1/maintenance-windows/${w.id}`, { method: "DELETE" }).catch(() => undefined);
    reload();
  }

  const done = () => {
    setEditing(null);
    reload();
  };

  return (
    <div className="page">
      <header className="page-header page-header-row">
        <div>
          <h1>{t("windows.title")}</h1>
          <p className="muted">{t("windows.subtitle")}</p>
        </div>
        {editable && (
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setEditing((v) => (v === "new" ? null : "new"))}
          >
            {t("windows.new")}
          </button>
        )}
      </header>
      {list.status === "error" && (
        <div className="alert alert-danger" role="alert">
          {t(list.error, { defaultValue: t("errors.unknown") })}
        </div>
      )}
      {editing === "new" && (
        <section className="card">
          <WindowForm onDone={done} />
        </section>
      )}
      <section className="card">
        <div className="table-wrap">
          <table className="table" aria-label={t("windows.title")}>
            <thead>
              <tr>
                <th>{t("windows.field.name")}</th>
                <th>{t("windows.col.when")}</th>
                <th>{t("windows.field.scope")}</th>
                <th>{t("windows.col.status")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.status === "ok" && list.data.items.length === 0 && (
                <tr>
                  <td colSpan={5} className="muted">
                    {t("windows.empty")}
                  </td>
                </tr>
              )}
              {list.status === "ok" &&
                list.data.items.map((w) =>
                  editing === w.id ? (
                    <tr key={w.id}>
                      <td colSpan={5}>
                        <WindowForm initial={w} onDone={done} />
                      </td>
                    </tr>
                  ) : (
                    <tr key={w.id}>
                      <td>
                        <strong>{w.name}</strong>
                      </td>
                      <td>
                        {DAYS.filter((d) => w.weekdays.includes(d))
                          .map((d) => t(`windows.dayShort.${d}`))
                          .join(", ")}{" "}
                        · {hhmm(w.start_minute)}–{hhmm((w.start_minute + w.duration_minutes) % 1440)}
                        <span className="muted small block">{w.timezone}</span>
                      </td>
                      <td className="small">
                        {w.scope_ous.length ? w.scope_ous.join("; ") : t("windows.allMachines")}
                      </td>
                      <td>
                        <span
                          className={`pill ${!w.enabled ? "pill-muted" : w.open_now ? "pill-success" : "pill-warning"}`}
                        >
                          {t(
                            !w.enabled
                              ? "windows.status.disabled"
                              : w.open_now
                                ? "windows.status.open"
                                : "windows.status.closed",
                          )}
                        </span>
                      </td>
                      <td className="report-actions">
                        {editable && (
                          <>
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm"
                              onClick={() => setEditing(w.id)}
                            >
                              {t("windows.edit")}
                            </button>
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm"
                              onClick={() => void remove(w)}
                            >
                              {t("windows.delete")}
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                  ),
                )}
            </tbody>
          </table>
        </div>
      </section>
      <p className="muted small">{t("windows.note")}</p>
    </div>
  );
}
