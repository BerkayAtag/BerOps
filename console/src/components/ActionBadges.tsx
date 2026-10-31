import { useTranslation } from "react-i18next";
import type { Action, ActionStatus, TargetStatus } from "../api/client";

const ACTION_TONE: Record<ActionStatus, string> = {
  pending_approval: "pill-warning",
  active: "pill-info",
  completed: "pill-success",
  cancelled: "pill-muted",
  rejected: "pill-danger",
};

const TARGET_TONE: Record<TargetStatus, string> = {
  pending: "pill-muted",
  downloading: "pill-info",
  running: "pill-info",
  succeeded: "pill-success",
  failed: "pill-danger",
  cancelled: "pill-muted",
  expired: "pill-warning",
};

export function ActionStatusPill({ status }: { status: ActionStatus }) {
  const { t } = useTranslation();
  return <span className={`pill ${ACTION_TONE[status]}`}>{t(`actions.status.${status}`)}</span>;
}

export function TargetStatusPill({ status }: { status: TargetStatus }) {
  const { t } = useTranslation();
  return <span className={`pill ${TARGET_TONE[status]}`}>{t(`actions.target.${status}`)}</span>;
}

/** Hedeflerin durumlarına göre bölünmüş ilerleme çubuğu. */
export function ActionProgress({ action }: { action: Action }) {
  const { t } = useTranslation();
  const c = action.counts;
  const total = action.target_count || 1;
  const ok = c.succeeded ?? 0;
  const bad = (c.failed ?? 0) + (c.expired ?? 0);
  const busy = (c.downloading ?? 0) + (c.running ?? 0);
  const done = ok + bad + (c.cancelled ?? 0);
  const seg = (n: number) => `${(n / total) * 100}%`;
  return (
    <span className="action-progress" title={t("actions.progress", { done, total: action.target_count })}>
      <span className="segbar" aria-hidden="true">
        <span className="seg seg-ok" style={{ width: seg(ok) }} />
        <span className="seg seg-bad" style={{ width: seg(bad) }} />
        <span className="seg seg-busy" style={{ width: seg(busy) }} />
      </span>
      <span className="small mono">{t("actions.progress", { done, total: action.target_count })}</span>
    </span>
  );
}
