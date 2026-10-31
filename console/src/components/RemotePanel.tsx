import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import {
  api,
  errorKey,
  type PerfSnapshot,
  type RegistryKey,
  type RemoteFlags,
  type RemoteStatus,
  type ServiceInfo,
} from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";
import { formatBytes, formatDateTime, formatNumber, formatPercent } from "../format";

type CallFn = <T>(op: string, params?: unknown) => Promise<T>;

function useCall(machineId: string): CallFn {
  return useCallback(
    <T,>(op: string, params?: unknown) =>
      api<T>(`/api/v1/machines/${machineId}/remote/call`, { method: "POST", body: { op, params } }),
    [machineId],
  );
}

function errText(t: ReturnType<typeof useTranslation>["t"], err: unknown) {
  const msg = err instanceof Error && "code" in err && err.code === "remote.failed" ? err.message : null;
  return msg ?? t(errorKey(err), { defaultValue: t("errors.unknown") });
}

function Bar({ used, total }: { used: number; total: number }) {
  const pct = total ? (used / total) * 100 : 0;
  return (
    <div className="gauge-bar" title={`${pct.toFixed(1)}%`}>
      <div
        className={`gauge-fill${pct > 90 ? " fill-danger" : pct > 75 ? " fill-warn" : ""}`}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

function Performance({ call }: { call: CallFn }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const [snap, setSnap] = useState<PerfSnapshot | null>(null);
  const [history, setHistory] = useState<number[]>([]);
  const [auto, setAuto] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    try {
      const s = await call<PerfSnapshot>("performance");
      setSnap(s);
      setHistory((h) => [...h.slice(-29), s.cpu_percent]);
      setError(null);
    } catch (err) {
      setError(errText(t, err));
    }
  }, [call, t]);
  useEffect(() => {
    // Uzaktan veri ajan üzerinden zaman uyumsuz yüklenir; sonuç geldiğinde durum güncellenir.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
    if (!auto) return;
    const h = window.setInterval(() => void load(), 5000);
    return () => window.clearInterval(h);
  }, [auto, load]);

  const spark = useMemo(() => {
    if (history.length < 2) return "";
    return history
      .map((v, i) => `${i === 0 ? "M" : "L"}${(i / (history.length - 1)) * 100},${30 - (v / 100) * 30}`)
      .join(" ");
  }, [history]);

  return (
    <section className="card">
      <div className="card-header card-header-row">
        <h2>{t("remote.perf.title")}</h2>
        <span className="report-actions">
          <label className="filter-check small">
            <input
              type="checkbox"
              className="checkbox"
              checked={auto}
              onChange={(e) => setAuto(e.target.checked)}
            />
            {t("remote.perf.auto")}
          </label>
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => void load()}>
            {t("remote.perf.refresh")}
          </button>
        </span>
      </div>
      {error && (
        <div className="card-body">
          <div className="alert alert-danger">{error}</div>
        </div>
      )}
      {snap && (
        <div className="card-body stack">
          <div className="perf-grid">
            <div>
              <p className="muted small">
                {t("remote.perf.cpu")} · {t("remote.perf.cores", { n: snap.cpu_cores })}
              </p>
              <p className="stat-value">{formatPercent(snap.cpu_percent, lng)}</p>
              {spark && (
                <svg className="sparkline" viewBox="0 0 100 30" preserveAspectRatio="none" aria-hidden="true">
                  <path d={spark} vectorEffect="non-scaling-stroke" />
                </svg>
              )}
            </div>
            <div>
              <p className="muted small">{t("remote.perf.memory")}</p>
              <p className="stat-value">
                {formatBytes(snap.mem_used, lng)}{" "}
                <span className="muted small">/ {formatBytes(snap.mem_total, lng)}</span>
              </p>
              <Bar used={snap.mem_used} total={snap.mem_total} />
              {snap.swap_total > 0 && (
                <p className="muted small">
                  {t("remote.perf.swap")}: {formatBytes(snap.swap_used, lng)} /{" "}
                  {formatBytes(snap.swap_total, lng)}
                </p>
              )}
            </div>
            <div>
              <p className="muted small">{t("remote.perf.uptime")}</p>
              <p className="stat-value">
                {t("remote.perf.uptimeValue", {
                  d: formatNumber(Math.floor(snap.uptime_seconds / 86400), lng),
                  h: Math.floor((snap.uptime_seconds % 86400) / 3600),
                })}
              </p>
              <p className="muted small">{formatDateTime(snap.collected_at, lng)}</p>
            </div>
          </div>
          <div>
            <p className="small strong">{t("remote.perf.disks")}</p>
            {snap.disks.map((d) => (
              <div key={d.mount} className="disk-row">
                <span className="dist-label mono small">{d.mount}</span>
                <Bar used={d.used} total={d.total} />
                <span className="dist-value small">
                  {formatBytes(d.total - d.used, lng)} / {formatBytes(d.total, lng)}
                </span>
              </div>
            ))}
          </div>
          <div className="table-wrap">
            <table className="table" aria-label={t("remote.perf.processes")}>
              <thead>
                <tr>
                  <th>{t("remote.perf.name")}</th>
                  <th>{t("remote.perf.pid")}</th>
                  <th>{t("remote.perf.user")}</th>
                  <th>{t("remote.perf.cpuCol")}</th>
                  <th>{t("remote.perf.rss")}</th>
                </tr>
              </thead>
              <tbody>
                {snap.processes.map((p) => (
                  <tr key={p.pid}>
                    <td className="strong cell-wrap">{p.name}</td>
                    <td className="mono">{p.pid}</td>
                    <td className="small">{p.user}</td>
                    <td className="mono">{formatPercent(p.cpu_percent, lng)}</td>
                    <td>{formatBytes(p.rss, lng)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  );
}

const STATE_TONE: Record<ServiceInfo["state"], string> = {
  running: "pill-success",
  stopped: "pill-muted",
  starting: "pill-info",
  stopping: "pill-warning",
  paused: "pill-warning",
  unknown: "pill-muted",
};

function Services({ call, canControl }: { call: CallFn; canControl: boolean }) {
  const { t } = useTranslation();
  const [list, setList] = useState<ServiceInfo[] | null>(null);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ kind: "info" | "danger"; text: string } | null>(null);
  const load = useCallback(async () => {
    try {
      setList(await call<ServiceInfo[]>("services.list"));
    } catch (err) {
      setNotice({ kind: "danger", text: errText(t, err) });
    }
  }, [call, t]);
  // Uzaktan veri ajan üzerinden zaman uyumsuz yüklenir; sonuç geldiğinde durum güncellenir.
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => void load(), [load]);

  async function control(s: ServiceInfo, action: "start" | "stop" | "restart") {
    if (
      !window.confirm(
        t("remote.svc.confirm", { name: s.display_name || s.name, action: t(`remote.svc.${action}`) }),
      )
    )
      return;
    setBusy(s.name);
    setNotice(null);
    try {
      await call("services.control", { name: s.name, action });
      setNotice({ kind: "info", text: t("remote.svc.done") });
      await load();
    } catch (err) {
      setNotice({ kind: "danger", text: errText(t, err) });
    } finally {
      setBusy(null);
    }
  }

  const needle = q.trim().toLocaleLowerCase();
  const shown = (list ?? []).filter(
    (s) =>
      !needle ||
      s.name.toLocaleLowerCase().includes(needle) ||
      (s.display_name ?? "").toLocaleLowerCase().includes(needle),
  );
  return (
    <section className="card">
      <div className="card-header card-header-row">
        <h2>
          {t("remote.svc.title")} {list && <span className="muted small">({list.length})</span>}
        </h2>
        <input
          className="input input-sm"
          type="search"
          placeholder={t("remote.svc.search")}
          aria-label={t("remote.svc.search")}
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      </div>
      {notice && (
        <div className="card-body">
          <div className={`alert alert-${notice.kind}`} role="status">
            {notice.text}
          </div>
        </div>
      )}
      <div className="table-wrap scroll-y">
        <table className="table" aria-label={t("remote.svc.title")}>
          <thead>
            <tr>
              <th>{t("remote.svc.name")}</th>
              <th>{t("remote.svc.state")}</th>
              <th>{t("remote.svc.startType")}</th>
              {canControl && <th>{t("remote.svc.actions")}</th>}
            </tr>
          </thead>
          <tbody>
            {shown.slice(0, 500).map((s) => (
              <tr key={s.name}>
                <td>
                  <span className="strong">{s.display_name || s.name}</span>
                  {s.display_name && <span className="muted small mono"> · {s.name}</span>}
                </td>
                <td>
                  <span className={`pill ${STATE_TONE[s.state]}`}>{t(`remote.svc.states.${s.state}`)}</span>
                </td>
                <td className="small">{s.start_type ?? ""}</td>
                {canControl && (
                  <td>
                    <span className="report-actions">
                      {s.state !== "running" && (
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm"
                          disabled={busy !== null}
                          onClick={() => void control(s, "start")}
                        >
                          {t("remote.svc.start")}
                        </button>
                      )}
                      {s.state === "running" && (
                        <>
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            disabled={busy !== null}
                            onClick={() => void control(s, "restart")}
                          >
                            {t("remote.svc.restart")}
                          </button>
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            disabled={busy !== null}
                            onClick={() => void control(s, "stop")}
                          >
                            {t("remote.svc.stop")}
                          </button>
                        </>
                      )}
                    </span>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

const REG_TYPES = ["REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ", "REG_DWORD", "REG_QWORD", "REG_BINARY"];

function Registry({ call, canWrite }: { call: CallFn; canWrite: boolean }) {
  const { t } = useTranslation();
  const [path, setPath] = useState("HKLM\\SOFTWARE");
  const [input, setInput] = useState(path);
  const [key, setKey] = useState<RegistryKey | null>(null);
  const [form, setForm] = useState({ name: "", type: "REG_SZ", data: "" });
  const [notice, setNotice] = useState<{ kind: "info" | "danger"; text: string } | null>(null);

  const open = useCallback(
    async (p: string) => {
      setNotice(null);
      try {
        const k = await call<RegistryKey>("registry.list", { path: p });
        setKey(k);
        setPath(p);
        setInput(p);
      } catch (err) {
        setNotice({ kind: "danger", text: errText(t, err) });
      }
    },
    [call, t],
  );
  // Uzaktan veri ajan üzerinden zaman uyumsuz yüklenir; sonuç geldiğinde durum güncellenir.
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => void open("HKLM\\SOFTWARE"), [open]);

  async function write(e: FormEvent) {
    e.preventDefault();
    if (!window.confirm(t("remote.reg.confirmSet", { path, name: form.name || t("remote.reg.default") })))
      return;
    try {
      await call("registry.set", { path, value: form });
      setNotice({ kind: "info", text: t("remote.reg.written") });
      await open(path);
    } catch (err) {
      setNotice({ kind: "danger", text: errText(t, err) });
    }
  }

  async function remove(name: string) {
    if (!window.confirm(t("remote.reg.confirmDelete", { name: name || t("remote.reg.default") }))) return;
    try {
      await call("registry.delete", { path, name });
      setNotice({ kind: "info", text: t("remote.reg.deleted") });
      await open(path);
    } catch (err) {
      setNotice({ kind: "danger", text: errText(t, err) });
    }
  }

  const parent = path.includes("\\") ? path.slice(0, path.lastIndexOf("\\")) : null;
  return (
    <section className="card">
      <div className="card-header">
        <h2>{t("remote.reg.title")}</h2>
      </div>
      <div className="card-body stack">
        <form
          className="report-actions"
          onSubmit={(e) => {
            e.preventDefault();
            void open(input.trim());
          }}
        >
          <input
            className="input input-sm mono grow-input"
            aria-label={t("remote.reg.path")}
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
          <button type="submit" className="btn btn-ghost btn-sm">
            {t("remote.reg.go")}
          </button>
          {parent && (
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => void open(parent)}>
              ↑ {t("remote.reg.up")}
            </button>
          )}
        </form>
        {notice && (
          <div className={`alert alert-${notice.kind}`} role="status">
            {notice.text}
          </div>
        )}
        {key?.truncated && <p className="muted small">{t("remote.reg.truncated")}</p>}
      </div>
      {key && (
        <div className="detail-grid reg-grid">
          <div>
            <p className="small strong card-body">{t("remote.reg.subkeys", { count: key.subkeys.length })}</p>
            <ul className="list-rows scroll-y">
              {key.subkeys.map((s) => (
                <li key={s} className="clickable" onClick={() => void open(`${path}\\${s}`)}>
                  <span className="mono small grow">📁 {s}</span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <p className="small strong card-body">{t("remote.reg.values", { count: key.values.length })}</p>
            <div className="table-wrap scroll-y">
              <table className="table" aria-label={t("remote.reg.values", { count: key.values.length })}>
                <thead>
                  <tr>
                    <th>{t("remote.reg.name")}</th>
                    <th>{t("remote.reg.type")}</th>
                    <th>{t("remote.reg.data")}</th>
                    {canWrite && <th />}
                  </tr>
                </thead>
                <tbody>
                  {key.values.map((v) => (
                    <tr key={v.name}>
                      <td className="mono small">{v.name || t("remote.reg.default")}</td>
                      <td className="small">{v.type}</td>
                      <td className="mono small cell-wrap">{v.data}</td>
                      {canWrite && (
                        <td>
                          <span className="report-actions">
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm"
                              onClick={() => setForm({ ...v })}
                            >
                              {t("remote.reg.edit")}
                            </button>
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm"
                              onClick={() => void remove(v.name)}
                            >
                              {t("remote.reg.delete")}
                            </button>
                          </span>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
      {canWrite ? (
        <form className="card-body form-grid" onSubmit={(e) => void write(e)}>
          <label>
            {t("remote.reg.name")}
            <input
              className="input input-sm mono"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </label>
          <label>
            {t("remote.reg.type")}
            <select
              className="select select-sm"
              value={form.type}
              onChange={(e) => setForm({ ...form, type: e.target.value })}
            >
              {REG_TYPES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </label>
          <label className="span-2">
            {t("remote.reg.data")}
            <input
              className="input input-sm mono"
              value={form.data}
              onChange={(e) => setForm({ ...form, data: e.target.value })}
            />
          </label>
          <div>
            <button type="submit" className="btn btn-primary btn-sm">
              {t("remote.reg.save")}
            </button>
          </div>
        </form>
      ) : (
        <p className="card-body muted small">{t("remote.reg.readOnly")}</p>
      )}
    </section>
  );
}

const FLAG_KEYS: (keyof RemoteFlags)[] = ["performance", "services", "registry_read", "registry_write"];

export function RemotePanel({ machineId }: { machineId: string }) {
  const { t, i18n } = useTranslation();
  const { can } = useAuth();
  const [status, reload] = useApi<RemoteStatus>(`/api/v1/machines/${machineId}/remote`);
  const [error, setError] = useState<string | null>(null);
  const call = useCall(machineId);
  const st = status.status === "ok" ? status.data : null;

  // Oturum açıldı ama ajan henüz bağlanmadıysa durum birkaç saniyede bir yenilenir.
  const waiting = Boolean(st?.active && !st.connected);
  useEffect(() => {
    if (!waiting) return;
    const h = window.setInterval(reload, 2000);
    return () => window.clearInterval(h);
  }, [waiting, reload]);

  if (!st) return <p className="card-body muted">{t("common.loading")}</p>;

  async function setFlag(k: keyof RemoteFlags, v: boolean) {
    setError(null);
    try {
      await api(`/api/v1/machines/${machineId}/remote/settings`, {
        method: "PUT",
        body: { ...st!.flags, [k]: v },
      });
      reload();
    } catch (err) {
      setError(errText(t, err));
    }
  }

  async function connect() {
    setError(null);
    try {
      await api(`/api/v1/machines/${machineId}/remote/session`, { method: "POST" });
      reload();
    } catch (err) {
      setError(errText(t, err));
    }
  }

  const f = st.flags;
  const anyFlag = f.performance || f.services || f.registry_read || f.registry_write;
  return (
    <div className="stack remote-panel">
      {!st.enabled && <div className="alert alert-info">{t("remote.disabledGlobal")}</div>}
      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}
      <section className="card">
        <div className="card-header">
          <h2>{t("remote.features")}</h2>
        </div>
        <div className="card-body stack">
          <p className="muted small">{t("remote.featuresHint")}</p>
          <div className="choice-row">
            {FLAG_KEYS.filter((k) => st.platform === "windows" || !k.startsWith("registry")).map((k) => (
              <label key={k} className="filter-check">
                <input
                  type="checkbox"
                  className="checkbox"
                  checked={f[k]}
                  disabled={!can("remote.settings")}
                  onChange={(e) => void setFlag(k, e.target.checked)}
                />
                {t(`remote.flag.${k}`)}
              </label>
            ))}
          </div>
          {st.enabled && anyFlag && (
            <div className="report-actions">
              {!st.active && (
                <button type="button" className="btn btn-primary btn-sm" onClick={() => void connect()}>
                  {t("remote.connect")}
                </button>
              )}
              {st.active && !st.connected && <span className="pill pill-info">{t("remote.connecting")}</span>}
              {st.connected && <span className="pill pill-success">{t("remote.connected")}</span>}
              {st.until && (
                <span className="muted small">
                  {t("remote.until", { time: formatDateTime(st.until, i18n.language) })}
                </span>
              )}
            </div>
          )}
          {st.enabled && !anyFlag && <p className="muted small">{t("remote.notAllowed")}</p>}
        </div>
      </section>
      {st.connected && f.performance && can("remote.performance") && <Performance call={call} />}
      {st.connected && f.services && can("remote.services") && (
        <Services call={call} canControl={can("remote.services")} />
      )}
      {st.connected &&
        st.platform === "windows" &&
        (f.registry_read || f.registry_write) &&
        can("remote.registry.read") && (
          <Registry call={call} canWrite={f.registry_write && can("remote.registry.write")} />
        )}
    </div>
  );
}
