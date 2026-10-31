import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, errorKey } from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";
import { formatDate, formatRelative } from "../format";

interface Relay {
  id: string;
  name: string;
  hostnames: string[];
  cert_expires_at: string;
  created_at: string;
  last_seen_at: string | null;
  last_ip: string;
  revoked_at: string | null;
  online: boolean;
}

export function RelaysPage() {
  const { t, i18n } = useTranslation();
  const { can } = useAuth();
  const [list, reload] = useApi<{ items: Relay[] }>("/api/v1/relays");
  const [error, setError] = useState<string | null>(null);

  async function revoke(r: Relay) {
    if (!window.confirm(t("relays.confirmRevoke", { name: r.name }))) return;
    setError(null);
    try {
      await api(`/api/v1/relays/${r.id}`, { method: "DELETE" });
      reload();
    } catch (err) {
      setError(t(errorKey(err), { defaultValue: t("errors.unknown") }));
    }
  }

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>{t("relays.title")}</h1>
          <p className="muted">{t("relays.subtitle")}</p>
        </div>
      </header>
      {(error || list.status === "error") && (
        <div className="alert alert-danger" role="alert">
          {error ?? (list.status === "error" ? t(list.error, { defaultValue: t("errors.unknown") }) : "")}
        </div>
      )}
      <section className="card card-body stack">
        <h2>{t("relays.howTitle")}</h2>
        <p className="muted small">{t("relays.how")}</p>
        <pre className="output-block">
          berops-server relay create -name relay-sube-1 -hostnames relay1.ornek.local -out ./relay-sube-1
        </pre>
      </section>
      <section className="card">
        <div className="table-wrap">
          <table className="table" aria-label={t("relays.title")}>
            <thead>
              <tr>
                <th>{t("relays.col.name")}</th>
                <th>{t("relays.col.hostnames")}</th>
                <th>{t("relays.col.status")}</th>
                <th>{t("relays.col.lastSeen")}</th>
                <th>{t("relays.col.certExpires")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.status === "loading" && (
                <tr>
                  <td colSpan={6} className="muted">
                    {t("common.loading")}
                  </td>
                </tr>
              )}
              {list.status === "ok" && list.data.items.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    {t("relays.empty")}
                  </td>
                </tr>
              )}
              {list.status === "ok" &&
                list.data.items.map((r) => {
                  const status = r.revoked_at ? "revoked" : r.online ? "online" : "offline";
                  return (
                    <tr key={r.id}>
                      <td>
                        <strong>{r.name}</strong>
                      </td>
                      <td className="mono small">{r.hostnames.join(", ")}</td>
                      <td>
                        <span
                          className={`pill ${status === "online" ? "pill-success" : status === "revoked" ? "pill-danger" : "pill-muted"}`}
                        >
                          {t(`relays.status.${status}`)}
                        </span>
                      </td>
                      <td>
                        {formatRelative(r.last_seen_at, i18n.language, t("common.never"))}
                        {r.last_ip && <span className="muted small block">{r.last_ip}</span>}
                      </td>
                      <td>{formatDate(r.cert_expires_at, i18n.language)}</td>
                      <td>
                        {!r.revoked_at && can("settings.write") && (
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            onClick={() => void revoke(r)}
                          >
                            {t("relays.revoke")}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
