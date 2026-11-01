import {
  createColumnHelper,
  type PaginationState,
  type RowSelectionState,
  type SortingState,
} from "@tanstack/react-table";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";
import {
  api,
  errorKey,
  type Group,
  type GroupsResponse,
  type MachineListItem,
  type Page,
} from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";
import { OnlinePill, PlatformIcon, RiskBadge, StatusPill } from "../components/Badges";
import { DataTable } from "../components/DataTable";
import { PAGE_SIZES } from "../components/pageSizes";
import { formatRelative } from "../format";
import { useListParams } from "../hooks/useListParams";

const col = createColumnHelper<MachineListItem>();

export function MachinesPage() {
  const { t, i18n } = useTranslation();
  const { can } = useAuth();
  const navigate = useNavigate();
  const p = useListParams();

  const q = p.get("q");
  const platform = p.get("platform");
  const status = p.get("status");
  const online = p.get("online");
  const groupId = p.get("group_id");
  const tag = p.get("tag");
  const sort = p.get("sort", "hostname");
  const desc = p.get("desc") === "true";
  const pageSize = PAGE_SIZES.includes(Number(p.get("size"))) ? Number(p.get("size")) : 50;
  const pageIndex = Math.max(0, Number(p.get("page", "1")) - 1);

  const [search, setSearch] = useState(q);
  useEffect(() => {
    const h = window.setTimeout(() => {
      if (search !== q) p.update({ q: search, page: null });
    }, 300);
    return () => window.clearTimeout(h);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  const query = new URLSearchParams({
    q,
    platform,
    status,
    online,
    group_id: groupId,
    tag,
    sort,
    desc: String(desc),
    page: String(pageIndex + 1),
    page_size: String(pageSize),
  });
  const [list, reload] = useApi<Page<MachineListItem>>(`/api/v1/machines?${query}`);
  const [selection, setSelection] = useState<RowSelectionState>({});
  const [groups] = useApi<GroupsResponse>("/api/v1/groups");
  const staticGroups = groups.status === "ok" ? groups.data.items.filter((g) => g.kind === "static") : [];
  const [notice, setNotice] = useState<{ kind: "info" | "danger"; text: string } | null>(null);
  const canScan = can("machines.manage");

  const sorting: SortingState = [{ id: sort, desc }];
  const pagination: PaginationState = { pageIndex, pageSize };

  const columns = useMemo(
    () => [
      col.accessor("hostname", {
        header: t("machines.col.hostname"),
        cell: (c) => (
          <span className="cell-host">
            <PlatformIcon platform={c.row.original.os_platform} />
            <Link
              to={`/makineler/${c.row.original.id}`}
              className="strong"
              onClick={(e) => e.stopPropagation()}
            >
              {c.getValue()}
            </Link>
          </span>
        ),
      }),
      col.accessor("os_name", {
        id: "os",
        header: t("machines.col.os"),
        cell: (c) => `${c.getValue()} ${c.row.original.os_version}`,
      }),
      col.accessor("os_build", {
        header: t("machines.col.build"),
        cell: (c) => <span className="mono">{c.getValue()}</span>,
      }),
      col.accessor("missing_count", {
        header: t("machines.col.missing"),
        cell: (c) =>
          c.row.original.inventory_at ? (
            <span className={`count ${c.getValue() > 0 ? "count-warn" : "count-ok"}`}>{c.getValue()}</span>
          ) : (
            <span className="muted small">{t("machines.noInventory")}</span>
          ),
      }),
      col.accessor("missing_critical_count", {
        id: "missing_critical",
        header: t("machines.col.critical"),
        cell: (c) =>
          c.row.original.inventory_at ? (
            <span className={`count ${c.getValue() > 0 ? "count-danger" : "count-ok"}`}>{c.getValue()}</span>
          ) : null,
      }),
      col.accessor("vuln_count", {
        id: "vulns",
        header: t("machines.col.vulns"),
        cell: (c) =>
          c.row.original.inventory_at ? (
            <span className="pills">
              <span className={`count ${c.getValue() > 0 ? "count-warn" : "count-ok"}`}>{c.getValue()}</span>
              {c.row.original.kev_count > 0 && <span className="tag">KEV {c.row.original.kev_count}</span>}
            </span>
          ) : null,
      }),
      col.accessor("max_risk", {
        id: "risk",
        header: t("machines.col.risk"),
        cell: (c) => (c.row.original.inventory_at ? <RiskBadge score={c.getValue()} /> : null),
      }),
      col.accessor("app_count", {
        header: t("machines.col.apps"),
        cell: (c) => (c.row.original.inventory_at ? c.getValue() : null),
      }),
      col.accessor("last_seen_at", {
        header: t("machines.col.lastSeen"),
        cell: (c) => (
          <span title={c.getValue() ?? undefined}>
            {formatRelative(c.getValue(), i18n.language, t("common.never"))}
          </span>
        ),
      }),
      col.accessor("status", {
        header: t("machines.col.status"),
        cell: (c) => (
          <span className="pills">
            <OnlinePill online={c.row.original.online} />
            <StatusPill status={c.getValue()} />
            {c.row.original.reboot_pending && (
              <span className="pill pill-info">{t("machines.rebootPending")}</span>
            )}
          </span>
        ),
      }),
    ],
    [t, i18n.language],
  );

  const selectedIds = Object.keys(selection).filter((k) => selection[k]);

  async function rescan() {
    setNotice(null);
    try {
      const r = await api<{ accepted: number }>("/api/v1/machines/scan", {
        method: "POST",
        body: { machine_ids: selectedIds },
      });
      setNotice({ kind: "info", text: t("machines.rescanQueued", { count: r.accepted }) });
      setSelection({});
    } catch (err) {
      setNotice({ kind: "danger", text: t(errorKey(err), { defaultValue: t("errors.unknown") }) });
    }
  }

  // Seçili makineleri statik gruba ekler.
  async function addToGroup(group: Group) {
    setNotice(null);
    try {
      await api(`/api/v1/groups/${group.id}/members`, { method: "PUT", body: { add: selectedIds } });
      setNotice({ kind: "info", text: t("groups.added", { count: selectedIds.length, name: group.name }) });
      setSelection({});
    } catch (err) {
      setNotice({ kind: "danger", text: t(errorKey(err), { defaultValue: t("errors.unknown") }) });
    }
  }

  const data = list.status === "ok" ? list.data : null;

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>{t("machines.title")}</h1>
          <p className="muted">{t("machines.subtitle")}</p>
        </div>
      </header>

      <section className="card">
        <div className="toolbar">
          <label className="search">
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <circle cx="11" cy="11" r="7" />
              <path d="m20 20-3.5-3.5" />
            </svg>
            <input
              className="input"
              type="search"
              aria-label={t("common.search")}
              placeholder={t("machines.searchPlaceholder")}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </label>
          <select
            className="select"
            aria-label={t("machines.filters.platform")}
            value={platform}
            onChange={(e) => p.update({ platform: e.target.value, page: null })}
          >
            <option value="">
              {t("machines.filters.platform")}: {t("common.all")}
            </option>
            <option value="windows">{t("machines.platform.windows")}</option>
            <option value="darwin">{t("machines.platform.darwin")}</option>
          </select>
          <select
            className="select"
            aria-label={t("machines.filters.status")}
            value={status}
            onChange={(e) => p.update({ status: e.target.value, page: null })}
          >
            <option value="">
              {t("machines.filters.status")}: {t("common.all")}
            </option>
            {["active", "pending", "rejected", "revoked"].map((s) => (
              <option key={s} value={s}>
                {t(`status.${s}`)}
              </option>
            ))}
          </select>
          <select
            className="select"
            aria-label={t("machines.filters.connection")}
            value={online}
            onChange={(e) => p.update({ online: e.target.value, page: null })}
          >
            <option value="">
              {t("machines.filters.connection")}: {t("common.all")}
            </option>
            <option value="true">{t("status.online")}</option>
            <option value="false">{t("status.offline")}</option>
          </select>
          {groups.status === "ok" && groups.data.items.length > 0 && (
            <select
              className="select"
              aria-label={t("groups.filter")}
              value={groupId}
              onChange={(e) => p.update({ group_id: e.target.value, page: null })}
            >
              <option value="">
                {t("groups.filter")}: {t("common.all")}
              </option>
              {groups.data.items.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          )}
          {groups.status === "ok" && groups.data.tags.length > 0 && (
            <select
              className="select"
              aria-label={t("groups.tagFilter")}
              value={tag}
              onChange={(e) => p.update({ tag: e.target.value, page: null })}
            >
              <option value="">
                {t("groups.tagFilter")}: {t("common.all")}
              </option>
              {groups.data.tags.map((x) => (
                <option key={x.tag} value={x.tag}>
                  {x.tag} ({x.machines})
                </option>
              ))}
            </select>
          )}
          <div className="toolbar-spacer" />
          {selectedIds.length > 0 && (
            <>
              <span className="muted small">{t("common.selected", { count: selectedIds.length })}</span>
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => setSelection({})}>
                {t("common.clearSelection")}
              </button>
              {canScan && staticGroups.length > 0 && (
                <select
                  className="select select-sm"
                  aria-label={t("groups.addTo")}
                  value=""
                  onChange={(e) => {
                    const g = staticGroups.find((x) => x.id === e.target.value);
                    if (g) void addToGroup(g);
                  }}
                >
                  <option value="">{t("groups.addTo")}</option>
                  {staticGroups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </select>
              )}
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                disabled={!canScan}
                title={canScan ? undefined : t("common.noPermission")}
                onClick={() => void rescan()}
              >
                {t("machines.rescanSelected")}
              </button>
              {can("actions.run_command") && (
                <Link
                  className="btn btn-ghost btn-sm"
                  to={`/aksiyonlar/yeni?kind=run_command&machines=${selectedIds.join(",")}`}
                >
                  {t("machines.runCommandSelected")}
                </Link>
              )}
              {can("actions.deploy_package") && (
                <Link
                  className="btn btn-primary btn-sm"
                  to={`/aksiyonlar/yeni?kind=deploy_package&machines=${selectedIds.join(",")}`}
                >
                  {t("machines.deploySelected")}
                </Link>
              )}
            </>
          )}
        </div>

        {notice && (
          <div className="card-body">
            <div className={`alert alert-${notice.kind}`} role="status">
              {notice.text}
            </div>
          </div>
        )}
        {list.status === "error" && (
          <div className="card-body">
            <div className="alert alert-danger" role="alert">
              {t(list.error, { defaultValue: t("errors.unknown") })}{" "}
              <button type="button" className="btn btn-ghost btn-sm" onClick={reload}>
                {t("common.retry")}
              </button>
            </div>
          </div>
        )}

        <DataTable
          label={t("machines.title")}
          data={data?.items ?? []}
          columns={columns}
          getRowId={(m) => m.id}
          serverTotal={data?.total ?? 0}
          loading={list.status === "loading"}
          sorting={sorting}
          onSortingChange={(u) => {
            const next = typeof u === "function" ? u(sorting) : u;
            const s = next[0];
            p.update({ sort: s?.id ?? null, desc: s?.desc ? "true" : null, page: null });
          }}
          pagination={pagination}
          onPaginationChange={(u) => {
            const next = typeof u === "function" ? u(pagination) : u;
            p.update({
              page: next.pageIndex > 0 ? String(next.pageIndex + 1) : null,
              size: next.pageSize !== 50 ? String(next.pageSize) : null,
            });
          }}
          rowSelection={selection}
          onRowSelectionChange={setSelection}
          onRowClick={(m) => navigate(`/makineler/${m.id}`)}
        />
      </section>
    </div>
  );
}
