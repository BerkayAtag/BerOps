import { createColumnHelper, type PaginationState } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";
import type { Action, Page } from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";
import { ActionProgress, ActionStatusPill } from "../components/ActionBadges";
import { DataTable } from "../components/DataTable";
import { formatDateTime } from "../format";

const col = createColumnHelper<Action>();

export function ActionsPage() {
  const { t, i18n } = useTranslation();
  const { can } = useAuth();
  const navigate = useNavigate();
  const [status, setStatus] = useState("");
  const [kind, setKind] = useState("");
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 50 });
  const q = new URLSearchParams({
    status,
    kind,
    page: String(pagination.pageIndex + 1),
    page_size: String(pagination.pageSize),
  });
  const [list] = useApi<Page<Action>>(`/api/v1/actions?${q}`);
  const canCreate = can("actions.deploy_package") || can("actions.run_command");

  const columns = useMemo(
    () => [
      col.accessor("name", {
        header: t("actions.col.name"),
        enableSorting: false,
        cell: (c) => (
          <span className="cell-wrap">
            <Link
              to={`/aksiyonlar/${c.row.original.id}`}
              className="strong"
              onClick={(e) => e.stopPropagation()}
            >
              {c.getValue()}
            </Link>
          </span>
        ),
      }),
      col.accessor("kind", {
        header: t("actions.col.kind"),
        enableSorting: false,
        cell: (c) => <span className="tag">{t(`actions.kind.${c.getValue()}`)}</span>,
      }),
      col.accessor("status", {
        header: t("actions.col.status"),
        enableSorting: false,
        cell: (c) => <ActionStatusPill status={c.getValue()} />,
      }),
      col.display({
        id: "progress",
        header: t("actions.col.progress"),
        cell: (c) => <ActionProgress action={c.row.original} />,
      }),
      col.accessor("created_by_name", { header: t("actions.col.createdBy"), enableSorting: false }),
      col.accessor("created_at", {
        header: t("actions.col.created"),
        enableSorting: false,
        cell: (c) => formatDateTime(c.getValue(), i18n.language),
      }),
    ],
    [t, i18n.language],
  );

  return (
    <div className="page">
      <header className="page-header page-header-row">
        <div>
          <h1>{t("actions.title")}</h1>
          <p className="muted">{t("actions.subtitle")}</p>
        </div>
        {canCreate && (
          <Link className="btn btn-primary" to="/aksiyonlar/yeni">
            {t("actions.new")}
          </Link>
        )}
      </header>
      <section className="card">
        <div className="toolbar">
          <select
            className="select"
            aria-label={t("actions.filterStatus")}
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPagination((p) => ({ ...p, pageIndex: 0 }));
            }}
          >
            <option value="">
              {t("actions.filterStatus")}: {t("common.all")}
            </option>
            {(["pending_approval", "active", "completed", "cancelled", "rejected"] as const).map((s) => (
              <option key={s} value={s}>
                {t(`actions.status.${s}`)}
              </option>
            ))}
          </select>
          <select
            className="select"
            aria-label={t("actions.filterKind")}
            value={kind}
            onChange={(e) => {
              setKind(e.target.value);
              setPagination((p) => ({ ...p, pageIndex: 0 }));
            }}
          >
            <option value="">
              {t("actions.filterKind")}: {t("common.all")}
            </option>
            <option value="deploy_package">{t("actions.kind.deploy_package")}</option>
            <option value="run_command">{t("actions.kind.run_command")}</option>
            <option value="deploy_patch">{t("actions.kind.deploy_patch")}</option>
          </select>
        </div>
        <DataTable
          label={t("actions.title")}
          data={list.status === "ok" ? list.data.items : []}
          columns={columns}
          getRowId={(a) => a.id}
          serverTotal={list.status === "ok" ? list.data.total : 0}
          loading={list.status === "loading"}
          emptyText={t("actions.empty")}
          sorting={[]}
          onSortingChange={() => {}}
          pagination={pagination}
          onPaginationChange={setPagination}
          onRowClick={(a) => navigate(`/aksiyonlar/${a.id}`)}
        />
      </section>
    </div>
  );
}
