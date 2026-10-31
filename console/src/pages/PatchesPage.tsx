import { Fragment, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";
import { api, errorKey, type Action } from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";
import { PlatformIcon, SeverityBadge } from "../components/Badges";
import { formatDate, formatNumber } from "../format";
import { ROLLOUT_PRESETS, type RolloutPreset } from "../rollout";

interface FleetPatch {
  update_id: string;
  kb: string;
  title: string;
  classification: string;
  severity: string;
  platform: "windows" | "darwin";
  released_at: string | null;
  reboot_required: boolean;
  cve_count: number;
  machines: number;
}

interface PatchMachine {
  id: string;
  hostname: string;
  os_platform: string;
  os_name: string;
}

function AffectedMachines({ updateId }: { updateId: string }) {
  const { t } = useTranslation();
  const [resp] = useApi<{ items: PatchMachine[] }>(
    `/api/v1/patches/machines?update_id=${encodeURIComponent(updateId)}`,
  );
  if (resp.status !== "ok") return <p className="muted small">{t("common.loading")}</p>;
  return (
    <div className="stage-list">
      {resp.data.items.map((m) => (
        <Link key={m.id} to={`/makineler/${m.id}`} className="tag">
          {m.hostname}
        </Link>
      ))}
    </div>
  );
}

export function PatchesPage() {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const { can } = useAuth();
  const navigate = useNavigate();
  const [platform, setPlatform] = useState("");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const params = new URLSearchParams({ platform, severity, q }).toString();
  const [resp] = useApi<{ items: FleetPatch[] }>(`/api/v1/patches?${params}`);
  const [selected, setSelected] = useState<string[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [preset, setPreset] = useState<RolloutPreset>("pilot");
  const [respectWindows, setRespectWindows] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const items = resp.status === "ok" ? resp.data.items : [];
  const chosen = items.filter((p) => selected.includes(p.update_id));
  const platforms = new Set(chosen.map((p) => p.platform));
  const canDeploy = can("actions.deploy_patch");

  function toggle(id: string) {
    setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));
  }

  async function deploy() {
    setBusy(true);
    setError(null);
    try {
      // Hedefler: seçilen güncellemelerden en az biri eksik olan makineler.
      const lists = await Promise.all(
        chosen.map((p) =>
          api<{ items: PatchMachine[] }>(
            `/api/v1/patches/machines?update_id=${encodeURIComponent(p.update_id)}`,
          ),
        ),
      );
      const machineIds = [...new Set(lists.flatMap((l) => l.items.map((m) => m.id)))];
      const label = chosen
        .map((p) => p.kb || p.title)
        .slice(0, 3)
        .join(", ");
      const body: Record<string, unknown> = {
        kind: "deploy_patch",
        name: t("patches.actionName", { list: label, count: chosen.length }),
        patches: chosen.map((p) => p.update_id),
        machine_ids: machineIds,
        respect_windows: respectWindows,
      };
      if (preset !== "none") body.rollout = ROLLOUT_PRESETS[preset];
      const a = await api<Action>("/api/v1/actions", { method: "POST", body });
      navigate(`/aksiyonlar/${a.id}`);
    } catch (err) {
      const invalid = err instanceof Error && "code" in err && err.code === "request.invalid";
      setError(invalid ? err.message : t(errorKey(err), { defaultValue: t("errors.unknown") }));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>{t("patches.title")}</h1>
          <p className="muted">{t("patches.subtitle")}</p>
        </div>
      </header>

      {canDeploy && chosen.length > 0 && (
        <section className="card card-body stack">
          <h2>{t("patches.deployTitle", { count: chosen.length })}</h2>
          {error && (
            <div className="alert alert-danger" role="alert">
              {error}
            </div>
          )}
          {platforms.size > 1 ? (
            <div className="alert alert-warning">{t("patches.mixedPlatforms")}</div>
          ) : (
            <>
              <div className="form-grid">
                <label>
                  {t("actions.wizard.rollout")}
                  <select
                    className="select select-sm"
                    value={preset}
                    onChange={(e) => setPreset(e.target.value as RolloutPreset)}
                  >
                    {(Object.keys(ROLLOUT_PRESETS) as RolloutPreset[]).map((p) => (
                      <option key={p} value={p}>
                        {t(`actions.rolloutPreset.${p}`)}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <label className="check">
                <input
                  type="checkbox"
                  className="checkbox"
                  checked={respectWindows}
                  onChange={(e) => setRespectWindows(e.target.checked)}
                />
                <span>
                  {t("actions.wizard.respectWindows")}
                  <small className="muted block">{t("actions.wizard.respectWindowsHint")}</small>
                </span>
              </label>
              {chosen.some((p) => p.platform === "darwin") && (
                <p className="muted small">{t("patches.macNote")}</p>
              )}
              <div className="report-actions">
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={busy}
                  onClick={() => void deploy()}
                >
                  {busy ? t("actions.wizard.submitting") : t("patches.deploy")}
                </button>
                <button type="button" className="btn btn-ghost" onClick={() => setSelected([])}>
                  {t("common.clearSelection")}
                </button>
              </div>
            </>
          )}
        </section>
      )}

      {resp.status === "error" && (
        <div className="alert alert-danger" role="alert">
          {t(resp.error, { defaultValue: t("errors.unknown") })}
        </div>
      )}
      <section className="card">
        <div className="toolbar">
          <input
            className="input input-sm"
            type="search"
            placeholder={t("patches.search")}
            aria-label={t("patches.search")}
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <select
            className="select select-sm"
            aria-label={t("patches.platform")}
            value={platform}
            onChange={(e) => setPlatform(e.target.value)}
          >
            <option value="">{t("patches.allPlatforms")}</option>
            <option value="windows">Windows</option>
            <option value="darwin">macOS</option>
          </select>
          <select
            className="select select-sm"
            aria-label={t("machine.missing.severity")}
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
          >
            <option value="">{t("patches.allSeverities")}</option>
            {["Critical", "Important", "Moderate", "Low"].map((s) => (
              <option key={s} value={s}>
                {t(`severity.${s}`)}
              </option>
            ))}
          </select>
        </div>
        <div className="table-wrap">
          <table className="table" aria-label={t("patches.title")}>
            <thead>
              <tr>
                {canDeploy && <th aria-label={t("patches.select")} />}
                <th>{t("machine.missing.title")}</th>
                <th>{t("machine.missing.severity")}</th>
                <th>{t("machine.missing.classification")}</th>
                <th>{t("machine.missing.released")}</th>
                <th>{t("machine.missing.cves")}</th>
                <th>{t("patches.machines")}</th>
              </tr>
            </thead>
            <tbody>
              {resp.status === "loading" && (
                <tr>
                  <td colSpan={7} className="muted">
                    {t("common.loading")}
                  </td>
                </tr>
              )}
              {resp.status === "ok" && items.length === 0 && (
                <tr>
                  <td colSpan={7} className="muted">
                    {t("patches.empty")}
                  </td>
                </tr>
              )}
              {items.map((p) => (
                <Fragment key={p.update_id}>
                  <tr>
                    {canDeploy && (
                      <td>
                        <input
                          type="checkbox"
                          className="checkbox"
                          aria-label={t("patches.select")}
                          checked={selected.includes(p.update_id)}
                          onChange={() => toggle(p.update_id)}
                        />
                      </td>
                    )}
                    <td>
                      <span className="cell-host">
                        <PlatformIcon platform={p.platform} />
                        <span className="cell-wrap">
                          {p.kb && <strong>{p.kb} </strong>}
                          {p.title}
                          {p.reboot_required && (
                            <span className="muted small block">{t("patches.reboot")}</span>
                          )}
                        </span>
                      </span>
                    </td>
                    <td>
                      <SeverityBadge severity={p.severity} />
                    </td>
                    <td className="small">{p.classification || "—"}</td>
                    <td>{formatDate(p.released_at, lng)}</td>
                    <td>{p.cve_count ? formatNumber(p.cve_count, lng) : "—"}</td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        aria-expanded={expanded === p.update_id}
                        onClick={() => setExpanded((x) => (x === p.update_id ? null : p.update_id))}
                      >
                        {formatNumber(p.machines, lng)}
                      </button>
                    </td>
                  </tr>
                  {expanded === p.update_id && (
                    <tr className="target-output">
                      <td colSpan={7}>
                        <AffectedMachines updateId={p.update_id} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
