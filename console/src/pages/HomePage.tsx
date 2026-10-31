import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, errorKey, type Machine, type Me, type ServerInfo } from "../api/client";
import { CopyField } from "../components/CopyField";

type Load<T> = { status: "loading" } | { status: "error"; error: string } | { status: "ok"; data: T };

function useLoad<T>(path: string): [Load<T>, () => void] {
  const [state, setState] = useState<Load<T>>({ status: "loading" });
  const [nonce, setNonce] = useState(0);
  useEffect(() => {
    let cancelled = false;
    api<T>(path)
      .then((data) => !cancelled && setState({ status: "ok", data }))
      .catch((err: unknown) => !cancelled && setState({ status: "error", error: errorKey(err) }));
    return () => {
      cancelled = true;
    };
  }, [path, nonce]);
  const reload = useCallback(() => {
    setState({ status: "loading" });
    setNonce((n) => n + 1);
  }, []);
  return [state, reload];
}

function formatDate(iso: string | null, lng: string, never: string) {
  if (!iso) return never;
  return new Intl.DateTimeFormat(lng === "tr" ? "tr-TR" : "en-GB", {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(new Date(iso));
}

export function HomePage({ me }: { me: Me }) {
  const { t, i18n } = useTranslation();
  const [machines, reloadMachines] = useLoad<{ items: Machine[] }>("/api/v1/machines");
  const [info] = useLoad<ServerInfo>("/api/v1/server-info");
  const name = me.user.display_name || me.user.username;

  const items = machines.status === "ok" ? machines.data.items : [];
  const online = items.filter((m) => m.online).length;
  const pending = items.filter((m) => m.status === "pending").length;
  const recent = [...items].sort((a, b) => b.enrolled_at.localeCompare(a.enrolled_at)).slice(0, 10);

  const stats = [
    { key: "total", value: items.length, tone: "neutral" },
    { key: "online", value: online, tone: "success" },
    { key: "offline", value: items.length - online, tone: "muted" },
    { key: "pending", value: pending, tone: "warning" },
  ] as const;

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>{t("home.title")}</h1>
          <p className="muted">{t("home.welcome", { name })}</p>
        </div>
      </header>

      {me.user.role === "readonly" && <div className="alert alert-info">{t("home.readonlyNotice")}</div>}

      <section className="stat-grid" aria-live="polite">
        {stats.map((s) => (
          <div key={s.key} className={`stat-card tone-${s.tone}`}>
            <span className="stat-label">{t(`home.stats.${s.key}`)}</span>
            <span className="stat-value">{machines.status === "ok" ? s.value : "—"}</span>
          </div>
        ))}
      </section>

      <section className="card">
        <div className="card-header">
          <h2>{t("home.recentMachines")}</h2>
        </div>
        {machines.status === "loading" && <p className="muted card-body">{t("common.loading")}</p>}
        {machines.status === "error" && (
          <div className="card-body">
            <div className="alert alert-danger" role="alert">
              {t(machines.error, { defaultValue: t("errors.unknown") })}{" "}
              <button type="button" className="btn btn-ghost btn-sm" onClick={reloadMachines}>
                {t("common.retry")}
              </button>
            </div>
          </div>
        )}
        {machines.status === "ok" && recent.length === 0 && (
          <p className="muted card-body">{t("home.noMachines")}</p>
        )}
        {recent.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>{t("home.table.hostname")}</th>
                  <th>{t("home.table.os")}</th>
                  <th>{t("home.table.build")}</th>
                  <th>{t("home.table.agent")}</th>
                  <th>{t("home.table.lastSeen")}</th>
                  <th>{t("home.table.status")}</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((m) => (
                  <tr key={m.id}>
                    <td className="strong">{m.hostname}</td>
                    <td>
                      {m.os_name} {m.os_version}
                    </td>
                    <td className="mono">{m.os_build}</td>
                    <td className="mono">{m.agent_version}</td>
                    <td>{formatDate(m.last_seen_at, i18n.language, t("common.never"))}</td>
                    <td>
                      <span className={`pill ${m.online ? "pill-success" : "pill-muted"}`}>
                        {t(m.online ? "status.online" : "status.offline")}
                      </span>
                      {m.status !== "active" && (
                        <span className={`pill pill-${m.status === "pending" ? "warning" : "danger"}`}>
                          {t(`status.${m.status}`)}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {info.status === "ok" && (
        <section className="card">
          <div className="card-header">
            <h2>{t("home.agentSetup")}</h2>
          </div>
          <div className="card-body stack">
            <p className="muted">{t("home.agentSetupHint")}</p>
            <CopyField label={t("home.agentUrl")} value={info.data.agent_url} />
            <CopyField label={t("home.caFingerprint")} value={info.data.ca_fingerprint} />
            <p className="muted small">
              {t("home.serverVersion")}: <span className="mono">{info.data.version}</span>
            </p>
          </div>
        </section>
      )}
    </div>
  );
}
