import { Fragment, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";
import { api, errorKey, type Action, type ActionTarget } from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";
import { ActionProgress, ActionStatusPill, TargetStatusPill } from "../components/ActionBadges";
import { PlatformIcon } from "../components/Badges";
import { RestartForm } from "../components/RestartForm";
import { formatDateTime, formatRelative } from "../format";

export function ActionDetailPage() {
  const { id = "" } = useParams();
  const { t, i18n } = useTranslation();
  const { state, can } = useAuth();
  const lng = i18n.language;
  const [detail, reload] = useApi<{ action: Action; targets: ActionTarget[] }>(`/api/v1/actions/${id}`);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [error, setError] = useState<string | null>(null);
  const [showRestart, setShowRestart] = useState(false);

  // Süren aksiyon birkaç saniyede bir yenilenir.
  const live = detail.status === "ok" && ["active", "pending_approval"].includes(detail.data.action.status);
  useEffect(() => {
    if (!live) return;
    const h = window.setInterval(reload, 4000);
    return () => window.clearInterval(h);
  }, [live, reload]);

  if (detail.status === "loading") return <p className="muted">{t("common.loading")}</p>;
  if (detail.status === "error") {
    return (
      <div className="page">
        <Link to="/aksiyonlar" className="back-link">
          ← {t("actions.title")}
        </Link>
        <div className="alert alert-danger" role="alert">
          {t(detail.error, { defaultValue: t("errors.unknown") })}
        </div>
      </div>
    );
  }
  const { action: a, targets } = detail.data;
  const mine = state.status === "authenticated" && a.created_by === state.me.user.id;
  const kindPerm = `actions.${a.kind}`;

  async function releaseNext() {
    if (!window.confirm(t("actions.releaseConfirm"))) return;
    setError(null);
    try {
      await api(`/api/v1/actions/${a.id}/release-next`, { method: "POST" });
      reload();
    } catch (err) {
      setError(t(errorKey(err), { defaultValue: t("errors.unknown") }));
    }
  }
  const stages = a.rollout?.stages ?? [];
  const rebootIds = targets.filter((x) => x.reboot_required).map((x) => x.machine_id);
  const canRelease =
    a.status === "active" && stages.length > 0 && a.released_stages < stages.length && can(kindPerm);

  async function transition(op: "approve" | "reject" | "cancel") {
    if (op === "cancel" && !window.confirm(t("actions.cancelConfirm"))) return;
    setError(null);
    try {
      await api(`/api/v1/actions/${a.id}/${op}`, { method: "POST" });
      reload();
    } catch (err) {
      setError(t(errorKey(err), { defaultValue: t("errors.unknown") }));
    }
  }

  return (
    <div className="page">
      <Link to="/aksiyonlar" className="back-link">
        ← {t("actions.title")}
      </Link>
      <header className="page-header page-header-row">
        <div>
          <h1 className="cell-wrap">{a.name}</h1>
          <span className="pills">
            <span className="tag">{t(`actions.kind.${a.kind}`)}</span>
            <ActionStatusPill status={a.status} />
            <ActionProgress action={a} />
          </span>
        </div>
        <div className="report-actions">
          {a.status === "pending_approval" && can("actions.approve") && !mine && (
            <>
              <button type="button" className="btn btn-primary" onClick={() => void transition("approve")}>
                {t("actions.approve")}
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => void transition("reject")}>
                {t("actions.reject")}
              </button>
            </>
          )}
          {canRelease && (
            <button type="button" className="btn btn-primary" onClick={() => void releaseNext()}>
              {t("actions.releaseNext")}
            </button>
          )}
          {(a.status === "pending_approval" || a.status === "active") && can(kindPerm) && (
            <button type="button" className="btn btn-ghost" onClick={() => void transition("cancel")}>
              {t("actions.cancel")}
            </button>
          )}
        </div>
      </header>
      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}
      {a.status === "pending_approval" && (
        <div className="alert alert-info">{t("actions.pendingApprovalNotice")}</div>
      )}
      {a.paused_reason && a.status === "active" && (
        <div className="alert alert-warning" role="status">
          {t("actions.paused", { reason: a.paused_reason })}
        </div>
      )}
      {stages.length > 0 && (
        <section className="card card-body stack">
          <h2>{t("actions.rollout")}</h2>
          <div className="stage-list">
            {stages.map((st, i) => {
              const inStage = targets.filter((x) => x.stage === i);
              const done = inStage.filter((x) => x.status === "succeeded").length;
              return (
                <span key={i} className={`pill ${i < a.released_stages ? "pill-success" : "pill-muted"}`}>
                  {t("actions.stage", { n: i + 1, percent: st.percent, hours: st.delay_hours })} · {done}/
                  {inStage.length}
                </span>
              );
            })}
          </div>
          <p className="muted small">
            {t("actions.rolloutHint", { min: a.rollout?.min_success_percent ?? 0 })}
          </p>
        </section>
      )}
      {a.respect_windows && <p className="muted small">{t("actions.respectsWindows")}</p>}
      {a.not_before &&
        a.status === "active" &&
        new Date(a.not_before).getTime() > Date.parse(a.created_at) && (
          <div className="alert alert-info" role="status">
            {t("actions.scheduledFor", { time: formatDateTime(a.not_before, lng) })}
          </div>
        )}
      {rebootIds.length > 0 && (
        <div className="alert alert-warning report-actions" role="status">
          <span className="grow">{t("actions.rebootPending", { count: rebootIds.length })}</span>
          {can("actions.deploy_patch") && !showRestart && (
            <button type="button" className="btn btn-primary btn-sm" onClick={() => setShowRestart(true)}>
              {t("restart.button")}
            </button>
          )}
        </div>
      )}
      {showRestart && <RestartForm machineIds={rebootIds} onCancel={() => setShowRestart(false)} />}

      <section className="card">
        <div className="card-header">
          <h2>{t("actions.detail")}</h2>
        </div>
        <dl className="card-body fields">
          {a.kind === "deploy_patch" && (
            <div className="field-row">
              <dt>{t("actions.patches")}</dt>
              <dd className="mono small">{a.patches.join(", ")}</dd>
            </div>
          )}
          {a.kind === "deploy_package" && (
            <div className="field-row">
              <dt>{t("actions.package")}</dt>
              <dd>
                {a.package_id ? (
                  <Link to={`/paketler/${a.package_id}`}>
                    {a.package_name} {a.package_version}
                  </Link>
                ) : (
                  "—"
                )}
              </dd>
            </div>
          )}
          <div className="field-row">
            <dt>{t("actions.command")}</dt>
            <dd>
              <pre className="output-block">{a.command || "—"}</pre>
              {a.shell && <span className="tag">{a.shell}</span>}
            </dd>
          </div>
          <div className="field-row">
            <dt>{t("actions.timeout")}</dt>
            <dd>{t("common.seconds", { n: a.timeout_seconds })}</dd>
          </div>
          <div className="field-row">
            <dt>{t("actions.bandwidth")}</dt>
            <dd>{a.bandwidth_kbps} kbps</dd>
          </div>
          <div className="field-row">
            <dt>{t("actions.col.createdBy")}</dt>
            <dd>
              {a.created_by_name} · {formatDateTime(a.created_at, lng)}
            </dd>
          </div>
          <div className="field-row">
            <dt>{t("actions.expires")}</dt>
            <dd>{formatDateTime(a.expires_at, lng)}</dd>
          </div>
          {a.approved_at && (
            <div className="field-row">
              <dt>{t("actions.approvedAt")}</dt>
              <dd>{formatDateTime(a.approved_at, lng)}</dd>
            </div>
          )}
        </dl>
      </section>

      <section className="card">
        <div className="table-wrap">
          <table className="table" aria-label={t("actions.col.machine")}>
            <thead>
              <tr>
                <th>{t("actions.col.machine")}</th>
                <th>{t("actions.col.status")}</th>
                <th>{t("actions.col.exitCode")}</th>
                <th>{t("actions.col.finished")}</th>
                <th>{t("actions.col.output")}</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((tg) => {
                const hasOut = Boolean(tg.stdout || tg.stderr || tg.error);
                return (
                  <Fragment key={tg.machine_id}>
                    <tr>
                      <td>
                        <span className="cell-host">
                          <PlatformIcon platform={tg.os_platform} />
                          <Link to={`/makineler/${tg.machine_id}`} className="strong">
                            {tg.hostname}
                          </Link>
                        </span>
                      </td>
                      <td>
                        <TargetStatusPill status={tg.status} />
                        {tg.reboot_required && (
                          <span className="pill pill-warning">{t("actions.rebootTag")}</span>
                        )}
                        {stages.length > 0 && (
                          <span className="muted small block">
                            {t(tg.released ? "actions.stageShort" : "actions.stageWaiting", {
                              n: tg.stage + 1,
                            })}
                          </span>
                        )}
                      </td>
                      <td className="mono">{tg.exit_code ?? "—"}</td>
                      <td title={formatDateTime(tg.finished_at, lng)}>
                        {tg.finished_at ? formatRelative(tg.finished_at, lng) : "—"}
                      </td>
                      <td>
                        {hasOut ? (
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            aria-expanded={Boolean(open[tg.machine_id])}
                            onClick={() => setOpen((o) => ({ ...o, [tg.machine_id]: !o[tg.machine_id] }))}
                          >
                            {open[tg.machine_id] ? t("actions.hideOutput") : t("actions.showOutput")}
                          </button>
                        ) : (
                          <span className="muted small">{t("actions.noOutput")}</span>
                        )}
                      </td>
                    </tr>
                    {open[tg.machine_id] && (
                      <tr className="target-output">
                        <td colSpan={5} className="stack">
                          {tg.error && (
                            <div>
                              <p className="small strong">{t("actions.error")}</p>
                              <pre className="output-block">{tg.error}</pre>
                            </div>
                          )}
                          {tg.stdout && (
                            <div>
                              <p className="small strong">{t("actions.stdout")}</p>
                              <pre className="output-block">{tg.stdout}</pre>
                            </div>
                          )}
                          {tg.stderr && (
                            <div>
                              <p className="small strong">{t("actions.stderr")}</p>
                              <pre className="output-block">{tg.stderr}</pre>
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
