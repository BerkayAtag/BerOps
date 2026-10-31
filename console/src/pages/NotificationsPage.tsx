import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, errorKey } from "../api/client";
import { useApi } from "../api/useApi";
import { formatDateTime, formatRelative } from "../format";

interface Channel {
  id: string;
  name: string;
  kind: "email" | "webhook";
  config: Record<string, unknown>;
  has_secret: boolean;
  events: string[];
  enabled: boolean;
  last_sent_at: string | null;
  last_error: string;
}

interface Schedule {
  id: string;
  report: string;
  format: string;
  lang: string;
  weekday: number | null;
  hour: number;
  timezone: string;
  channel_id: string;
  last_run_at: string | null;
}

interface NotificationsResponse {
  items: Channel[];
  events: string[];
  schedules: Schedule[];
}

const REPORTS = ["compliance", "vulnerabilities", "missing-patches", "apps"];

function useFail() {
  const { t } = useTranslation();
  const [error, setError] = useState<string | null>(null);
  const fail = (err: unknown) => {
    const invalid = err instanceof Error && "code" in err && err.code === "request.invalid";
    setError(invalid ? err.message : t(errorKey(err), { defaultValue: t("errors.unknown") }));
  };
  return { error, setError, fail };
}

function ChannelForm({
  initial,
  events,
  onDone,
}: {
  initial?: Channel;
  events: string[];
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const c = initial?.config ?? {};
  const [f, setF] = useState({
    name: initial?.name ?? "",
    kind: initial?.kind ?? ("email" as Channel["kind"]),
    smtp_host: String(c.smtp_host ?? ""),
    smtp_port: Number(c.smtp_port ?? 587),
    security: String(c.security ?? "starttls"),
    username: String(c.username ?? ""),
    from: String(c.from ?? ""),
    to: Array.isArray(c.to) ? (c.to as string[]).join("\n") : "",
    url: String(c.url ?? ""),
    format: String(c.format ?? "generic"),
    secret: "",
    events: initial?.events ?? events,
    enabled: initial?.enabled ?? true,
  });
  const { error, setError, fail } = useFail();

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const config =
      f.kind === "email"
        ? {
            smtp_host: f.smtp_host,
            smtp_port: f.smtp_port,
            security: f.security,
            username: f.username,
            from: f.from,
            to: f.to
              .split(/[\n,;]/)
              .map((s) => s.trim())
              .filter(Boolean),
          }
        : { url: f.url, format: f.format };
    try {
      await api(initial ? `/api/v1/notifications/channels/${initial.id}` : "/api/v1/notifications/channels", {
        method: initial ? "PUT" : "POST",
        body: { name: f.name, kind: f.kind, config, secret: f.secret, events: f.events, enabled: f.enabled },
      });
      onDone();
    } catch (err) {
      fail(err);
    }
  }

  const toggleEvent = (ev: string) =>
    setF({ ...f, events: f.events.includes(ev) ? f.events.filter((x) => x !== ev) : [...f.events, ev] });

  return (
    <form className="card-body stack" onSubmit={(e) => void submit(e)}>
      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}
      <div className="form-grid">
        <label>
          {t("notify.field.name")}
          <input
            className="input input-sm"
            required
            value={f.name}
            onChange={(e) => setF({ ...f, name: e.target.value })}
          />
        </label>
        <label>
          {t("notify.field.kind")}
          <select
            className="select select-sm"
            value={f.kind}
            disabled={!!initial}
            onChange={(e) => setF({ ...f, kind: e.target.value as Channel["kind"] })}
          >
            <option value="email">{t("notify.kind.email")}</option>
            <option value="webhook">{t("notify.kind.webhook")}</option>
          </select>
        </label>
        {f.kind === "email" ? (
          <>
            <label>
              {t("notify.field.smtpHost")}
              <input
                className="input input-sm"
                required
                value={f.smtp_host}
                onChange={(e) => setF({ ...f, smtp_host: e.target.value })}
              />
            </label>
            <label>
              {t("notify.field.smtpPort")}
              <input
                className="input input-sm"
                type="number"
                min={1}
                max={65535}
                value={f.smtp_port}
                onChange={(e) => setF({ ...f, smtp_port: Number(e.target.value) })}
              />
            </label>
            <label>
              {t("notify.field.security")}
              <select
                className="select select-sm"
                value={f.security}
                onChange={(e) => setF({ ...f, security: e.target.value })}
              >
                <option value="starttls">STARTTLS</option>
                <option value="tls">TLS</option>
                <option value="none">{t("notify.security.none")}</option>
              </select>
            </label>
            <label>
              {t("notify.field.username")}
              <input
                className="input input-sm"
                autoComplete="off"
                value={f.username}
                onChange={(e) => setF({ ...f, username: e.target.value })}
              />
            </label>
            <label>
              {t("notify.field.password")}
              <input
                className="input input-sm"
                type="password"
                autoComplete="new-password"
                placeholder={initial?.has_secret ? t("notify.secretKept") : ""}
                value={f.secret}
                onChange={(e) => setF({ ...f, secret: e.target.value })}
              />
            </label>
            <label>
              {t("notify.field.from")}
              <input
                className="input input-sm"
                required
                placeholder="ber@ornek.local"
                value={f.from}
                onChange={(e) => setF({ ...f, from: e.target.value })}
              />
            </label>
            <label className="span-2">
              {t("notify.field.to")}
              <textarea
                className="textarea"
                rows={2}
                required
                value={f.to}
                onChange={(e) => setF({ ...f, to: e.target.value })}
              />
            </label>
          </>
        ) : (
          <>
            <label className="span-2">
              {t("notify.field.url")}
              <input
                className="input input-sm"
                required
                placeholder="https://"
                value={f.url}
                onChange={(e) => setF({ ...f, url: e.target.value })}
              />
            </label>
            <label>
              {t("notify.field.format")}
              <select
                className="select select-sm"
                value={f.format}
                onChange={(e) => setF({ ...f, format: e.target.value })}
              >
                <option value="generic">{t("notify.format.generic")}</option>
                <option value="teams">Microsoft Teams</option>
                <option value="slack">Slack</option>
              </select>
            </label>
            <label>
              {t("notify.field.hmac")}
              <input
                className="input input-sm"
                type="password"
                autoComplete="new-password"
                placeholder={initial?.has_secret ? t("notify.secretKept") : ""}
                value={f.secret}
                onChange={(e) => setF({ ...f, secret: e.target.value })}
              />
              <small className="muted">{t("notify.hmacHint")}</small>
            </label>
          </>
        )}
      </div>
      <fieldset className="day-picker">
        <legend>{t("notify.field.events")}</legend>
        {events.map((ev) => (
          <label key={ev} className="check">
            <input
              type="checkbox"
              className="checkbox"
              checked={f.events.includes(ev)}
              onChange={() => toggleEvent(ev)}
            />
            <span>{t(`notify.event.${ev.replace(".", "_")}`)}</span>
          </label>
        ))}
      </fieldset>
      <label className="check">
        <input
          type="checkbox"
          className="checkbox"
          checked={f.enabled}
          onChange={(e) => setF({ ...f, enabled: e.target.checked })}
        />
        <span>{t("notify.field.enabled")}</span>
      </label>
      <div>
        <button type="submit" className="btn btn-primary btn-sm">
          {t("common.save")}
        </button>
      </div>
    </form>
  );
}

function ScheduleForm({ channels, onDone }: { channels: Channel[]; onDone: () => void }) {
  const { t, i18n } = useTranslation();
  const emails = channels.filter((c) => c.kind === "email");
  const [f, setF] = useState({
    report: "compliance",
    format: "pdf",
    lang: i18n.language.startsWith("en") ? "en" : "tr",
    weekday: "1",
    hour: 8,
    timezone: "Europe/Istanbul",
    channel_id: emails[0]?.id ?? "",
  });
  const { error, setError, fail } = useFail();
  if (emails.length === 0) return <p className="card-body muted small">{t("notify.schedule.needEmail")}</p>;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api("/api/v1/notifications/schedules", {
        method: "POST",
        body: { ...f, weekday: f.weekday === "" ? null : Number(f.weekday) },
      });
      onDone();
    } catch (err) {
      fail(err);
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
          {t("notify.schedule.report")}
          <select
            className="select select-sm"
            value={f.report}
            onChange={(e) => setF({ ...f, report: e.target.value })}
          >
            {REPORTS.map((r) => (
              <option key={r} value={r}>
                {t(`notify.report.${r}`)}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("notify.schedule.format")}
          <select
            className="select select-sm"
            value={f.format}
            onChange={(e) => setF({ ...f, format: e.target.value })}
          >
            <option value="pdf">PDF</option>
            <option value="xlsx">Excel</option>
            <option value="csv">CSV</option>
          </select>
        </label>
        <label>
          {t("notify.schedule.lang")}
          <select
            className="select select-sm"
            value={f.lang}
            onChange={(e) => setF({ ...f, lang: e.target.value })}
          >
            <option value="tr">Türkçe</option>
            <option value="en">English</option>
          </select>
        </label>
        <label>
          {t("notify.schedule.weekday")}
          <select
            className="select select-sm"
            value={f.weekday}
            onChange={(e) => setF({ ...f, weekday: e.target.value })}
          >
            <option value="">{t("notify.schedule.daily")}</option>
            {[1, 2, 3, 4, 5, 6, 0].map((d) => (
              <option key={d} value={d}>
                {t(`windows.day.${d}`)}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("notify.schedule.hour")}
          <input
            className="input input-sm"
            type="number"
            min={0}
            max={23}
            value={f.hour}
            onChange={(e) => setF({ ...f, hour: Number(e.target.value) })}
          />
        </label>
        <label>
          {t("notify.schedule.channel")}
          <select
            className="select select-sm"
            value={f.channel_id}
            onChange={(e) => setF({ ...f, channel_id: e.target.value })}
          >
            {emails.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div>
        <button type="submit" className="btn btn-primary btn-sm">
          {t("notify.schedule.add")}
        </button>
      </div>
    </form>
  );
}

export function NotificationsPage() {
  const { t, i18n } = useTranslation();
  const [resp, reload] = useApi<NotificationsResponse>("/api/v1/notifications");
  const [editing, setEditing] = useState<string | null>(null);
  const [showSchedule, setShowSchedule] = useState(false);
  const [notice, setNotice] = useState<{ kind: "info" | "danger"; text: string } | null>(null);

  if (resp.status !== "ok") {
    return resp.status === "error" ? (
      <div className="alert alert-danger" role="alert">
        {t(resp.error, { defaultValue: t("errors.unknown") })}
      </div>
    ) : (
      <p className="muted">{t("common.loading")}</p>
    );
  }
  const { items, events, schedules } = resp.data;
  const done = () => {
    setEditing(null);
    setShowSchedule(false);
    reload();
  };

  async function test(c: Channel) {
    setNotice(null);
    try {
      const r = await api<{ ok: boolean; message: string }>(`/api/v1/notifications/channels/${c.id}/test`, {
        method: "POST",
      });
      setNotice({ kind: r.ok ? "info" : "danger", text: r.ok ? t("notify.testOk") : r.message });
      reload();
    } catch (err) {
      setNotice({ kind: "danger", text: t(errorKey(err), { defaultValue: t("errors.unknown") }) });
    }
  }

  async function remove(path: string, name: string) {
    if (!window.confirm(t("notify.confirmDelete", { name }))) return;
    await api(path, { method: "DELETE" }).catch(() => undefined);
    reload();
  }

  return (
    <div className="page">
      <header className="page-header page-header-row">
        <div>
          <h1>{t("notify.title")}</h1>
          <p className="muted">{t("notify.subtitle")}</p>
        </div>
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => setEditing((v) => (v === "new" ? null : "new"))}
        >
          {t("notify.newChannel")}
        </button>
      </header>
      {notice && (
        <div className={`alert alert-${notice.kind}`} role="status">
          {notice.text}
        </div>
      )}
      {editing === "new" && (
        <section className="card">
          <ChannelForm events={events} onDone={done} />
        </section>
      )}
      <section className="card">
        <div className="card-header">
          <h2>{t("notify.channels")}</h2>
        </div>
        <div className="table-wrap">
          <table className="table" aria-label={t("notify.channels")}>
            <thead>
              <tr>
                <th>{t("notify.field.name")}</th>
                <th>{t("notify.field.kind")}</th>
                <th>{t("notify.field.events")}</th>
                <th>{t("notify.col.last")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.length === 0 && (
                <tr>
                  <td colSpan={5} className="muted">
                    {t("notify.empty")}
                  </td>
                </tr>
              )}
              {items.map((c) =>
                editing === c.id ? (
                  <tr key={c.id}>
                    <td colSpan={5}>
                      <ChannelForm initial={c} events={events} onDone={done} />
                    </td>
                  </tr>
                ) : (
                  <tr key={c.id}>
                    <td>
                      <strong>{c.name}</strong>
                      {!c.enabled && <span className="pill pill-muted">{t("notify.disabled")}</span>}
                    </td>
                    <td>{t(`notify.kind.${c.kind}`)}</td>
                    <td className="small">
                      <span className="cell-wrap">
                        {c.events.map((ev) => t(`notify.event.${ev.replace(".", "_")}`)).join(", ") || "—"}
                      </span>
                    </td>
                    <td>
                      {formatRelative(c.last_sent_at, i18n.language, t("common.never"))}
                      {c.last_error && <span className="text-danger small block">{c.last_error}</span>}
                    </td>
                    <td className="report-actions">
                      <button type="button" className="btn btn-ghost btn-sm" onClick={() => void test(c)}>
                        {t("notify.test")}
                      </button>
                      <button type="button" className="btn btn-ghost btn-sm" onClick={() => setEditing(c.id)}>
                        {t("windows.edit")}
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        onClick={() => void remove(`/api/v1/notifications/channels/${c.id}`, c.name)}
                      >
                        {t("windows.delete")}
                      </button>
                    </td>
                  </tr>
                ),
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card">
        <div className="card-header page-header-row">
          <h2>{t("notify.schedules")}</h2>
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => setShowSchedule((v) => !v)}>
            {t("notify.schedule.add")}
          </button>
        </div>
        {showSchedule && <ScheduleForm channels={items} onDone={done} />}
        <div className="table-wrap">
          <table className="table" aria-label={t("notify.schedules")}>
            <thead>
              <tr>
                <th>{t("notify.schedule.report")}</th>
                <th>{t("notify.schedule.when")}</th>
                <th>{t("notify.schedule.channel")}</th>
                <th>{t("notify.schedule.lastRun")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {schedules.length === 0 && (
                <tr>
                  <td colSpan={5} className="muted">
                    {t("notify.schedule.empty")}
                  </td>
                </tr>
              )}
              {schedules.map((s) => (
                <tr key={s.id}>
                  <td>
                    {t(`notify.report.${s.report}`)} · {s.format.toUpperCase()} · {s.lang.toUpperCase()}
                  </td>
                  <td>
                    {s.weekday === null ? t("notify.schedule.daily") : t(`windows.day.${s.weekday}`)} ·{" "}
                    {String(s.hour).padStart(2, "0")}:00 <span className="muted small">{s.timezone}</span>
                  </td>
                  <td>{items.find((c) => c.id === s.channel_id)?.name ?? "—"}</td>
                  <td>{formatDateTime(s.last_run_at, i18n.language, t("common.never"))}</td>
                  <td>
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      onClick={() =>
                        void remove(`/api/v1/notifications/schedules/${s.id}`, t(`notify.report.${s.report}`))
                      }
                    >
                      {t("windows.delete")}
                    </button>
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
