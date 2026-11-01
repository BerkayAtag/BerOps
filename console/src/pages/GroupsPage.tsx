import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import {
  api,
  errorKey,
  type Group,
  type GroupCondition,
  type GroupField,
  type GroupRule,
  type GroupsResponse,
  type MachineListItem,
} from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";

// Alan → izin verilen işlemler (sunucudaki beyaz listeyle aynı).
const FIELDS: Record<GroupField, string[]> = {
  platform: ["eq"],
  os_name: ["contains", "eq"],
  os_build: ["version_lt", "version_gte", "prefix"],
  hostname: ["contains", "prefix", "eq"],
  ad_ou: ["under"],
  tag: ["has"],
  app: ["version_lt", "version_gte", "installed", "missing"],
  missing_patch: ["has"],
  agent_version: ["version_lt", "version_gte"],
  risk: ["gte"],
};

const emptyCondition = (): GroupCondition => ({ field: "platform", op: "eq", value: "windows" });

function needsValue(c: GroupCondition) {
  return !(c.field === "app" && (c.op === "installed" || c.op === "missing"));
}

function GroupForm({ initial, onDone }: { initial?: Group; onDone: () => void }) {
  const { t } = useTranslation();
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [kind, setKind] = useState<Group["kind"]>(initial?.kind ?? "dynamic");
  const [rule, setRule] = useState<GroupRule>(
    initial?.rule ?? { match: "all", conditions: [emptyCondition()] },
  );
  const [preview, setPreview] = useState<{ total: number; items: MachineListItem[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fail = (err: unknown) => {
    const invalid = err instanceof Error && "code" in err && err.code === "request.invalid";
    setError(invalid ? err.message : t(errorKey(err), { defaultValue: t("errors.unknown") }));
  };

  function setCondition(i: number, patch: Partial<GroupCondition>) {
    setPreview(null);
    setRule((r) => ({
      ...r,
      conditions: r.conditions.map((c, j) => {
        if (j !== i) return c;
        const next = { ...c, ...patch };
        // Alan değişince ilk geçerli işleme dönülür.
        if (patch.field) next.op = FIELDS[patch.field][0] ?? "eq";
        return next;
      }),
    }));
  }

  async function runPreview() {
    setError(null);
    try {
      setPreview(await api("/api/v1/groups/preview", { method: "POST", body: rule }));
    } catch (err) {
      fail(err);
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api(initial ? `/api/v1/groups/${initial.id}` : "/api/v1/groups", {
        method: initial ? "PUT" : "POST",
        body: { name, description, kind, rule: kind === "dynamic" ? rule : null },
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
          {t("groups.name")}
          <input
            className="input input-sm"
            required
            maxLength={100}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <label>
          {t("groups.kind")}
          <select
            className="select select-sm"
            value={kind}
            onChange={(e) => setKind(e.target.value as Group["kind"])}
          >
            <option value="dynamic">{t("groups.kindDynamic")}</option>
            <option value="static">{t("groups.kindStatic")}</option>
          </select>
        </label>
        <label className="span-2">
          {t("groups.description")}
          <input
            className="input input-sm"
            maxLength={500}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </label>
      </div>

      {kind === "static" ? (
        <p className="muted small">{t("groups.staticHint")}</p>
      ) : (
        <div className="stack">
          <label className="check">
            <span>{t("groups.match")}</span>
            <select
              className="select select-sm"
              value={rule.match}
              onChange={(e) => setRule({ ...rule, match: e.target.value as GroupRule["match"] })}
            >
              <option value="all">{t("groups.matchAll")}</option>
              <option value="any">{t("groups.matchAny")}</option>
            </select>
          </label>
          {rule.conditions.map((c, i) => (
            <div key={i} className="report-actions rule-row">
              <select
                className="select select-sm"
                aria-label={t("groups.field")}
                value={c.field}
                onChange={(e) => setCondition(i, { field: e.target.value as GroupField })}
              >
                {(Object.keys(FIELDS) as GroupField[]).map((f) => (
                  <option key={f} value={f}>
                    {t(`groups.fields.${f}`)}
                  </option>
                ))}
              </select>
              {c.field === "app" && (
                <input
                  className="input input-sm"
                  aria-label={t("groups.appName")}
                  placeholder={t("groups.appName")}
                  value={c.name ?? ""}
                  onChange={(e) => setCondition(i, { name: e.target.value })}
                />
              )}
              <select
                className="select select-sm"
                aria-label={t("groups.op")}
                value={c.op}
                onChange={(e) => setCondition(i, { op: e.target.value })}
              >
                {FIELDS[c.field].map((op) => (
                  <option key={op} value={op}>
                    {t(`groups.ops.${op}`)}
                  </option>
                ))}
              </select>
              {needsValue(c) &&
                (c.field === "platform" ? (
                  <select
                    className="select select-sm"
                    aria-label={t("groups.value")}
                    value={c.value}
                    onChange={(e) => setCondition(i, { value: e.target.value })}
                  >
                    <option value="windows">Windows</option>
                    <option value="darwin">macOS</option>
                  </select>
                ) : (
                  <input
                    className="input input-sm"
                    aria-label={t("groups.value")}
                    placeholder={t(`groups.placeholders.${c.field}`)}
                    value={c.value}
                    onChange={(e) => setCondition(i, { value: e.target.value })}
                  />
                ))}
              {rule.conditions.length > 1 && (
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  aria-label={t("groups.removeCondition")}
                  onClick={() => setRule({ ...rule, conditions: rule.conditions.filter((_, j) => j !== i) })}
                >
                  ×
                </button>
              )}
            </div>
          ))}
          <div className="report-actions">
            {rule.conditions.length < 10 && (
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setRule({ ...rule, conditions: [...rule.conditions, emptyCondition()] })}
              >
                {t("groups.addCondition")}
              </button>
            )}
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => void runPreview()}>
              {t("groups.preview")}
            </button>
          </div>
          {preview && (
            <div className="alert alert-info" role="status">
              <strong>{t("groups.previewCount", { count: preview.total })}</strong>
              {preview.items.length > 0 && (
                <span className="block small">
                  {preview.items.map((m) => m.hostname).join(", ")}
                  {preview.total > preview.items.length && " …"}
                </span>
              )}
            </div>
          )}
        </div>
      )}
      <div>
        <button type="submit" className="btn btn-primary btn-sm">
          {t("common.save")}
        </button>
      </div>
    </form>
  );
}

export function GroupsPage() {
  const { t } = useTranslation();
  const { can } = useAuth();
  const [list, reload] = useApi<GroupsResponse>("/api/v1/groups");
  const [editing, setEditing] = useState<string | null>(null);
  const editable = can("machines.manage");

  async function remove(g: Group) {
    if (!window.confirm(t("groups.confirmDelete", { name: g.name }))) return;
    await api(`/api/v1/groups/${g.id}`, { method: "DELETE" }).catch(() => undefined);
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
          <h1>{t("groups.title")}</h1>
          <p className="muted">{t("groups.subtitle")}</p>
        </div>
        {editable && (
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setEditing((v) => (v === "new" ? null : "new"))}
          >
            {t("groups.new")}
          </button>
        )}
      </header>
      {editing === "new" && (
        <section className="card">
          <GroupForm onDone={done} />
        </section>
      )}
      {list.status === "error" && (
        <div className="alert alert-danger" role="alert">
          {t(list.error, { defaultValue: t("errors.unknown") })}
        </div>
      )}
      <section className="card">
        <div className="table-wrap">
          <table className="table" aria-label={t("groups.title")}>
            <thead>
              <tr>
                <th>{t("groups.name")}</th>
                <th>{t("groups.kind")}</th>
                <th>{t("groups.members")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.status === "ok" && list.data.items.length === 0 && (
                <tr>
                  <td colSpan={4} className="muted">
                    {t("groups.empty")}
                  </td>
                </tr>
              )}
              {list.status === "ok" &&
                list.data.items.map((g) =>
                  editing === g.id ? (
                    <tr key={g.id}>
                      <td colSpan={4}>
                        <GroupForm initial={g} onDone={done} />
                      </td>
                    </tr>
                  ) : (
                    <tr key={g.id}>
                      <td>
                        <strong>{g.name}</strong>
                        {g.description && <span className="muted small block">{g.description}</span>}
                      </td>
                      <td>
                        <span className="tag">
                          {t(g.kind === "dynamic" ? "groups.kindDynamic" : "groups.kindStatic")}
                        </span>
                        {g.rule && (
                          <span className="muted small block">
                            {g.rule.conditions
                              .map(
                                (c) =>
                                  `${t(`groups.fields.${c.field}`)}${c.name ? ` "${c.name}"` : ""} ${t(`groups.ops.${c.op}`)} ${c.value}`,
                              )
                              .join(g.rule.match === "all" ? ` ${t("groups.and")} ` : ` ${t("groups.or")} `)}
                          </span>
                        )}
                      </td>
                      <td>
                        <Link to={`/makineler?group_id=${g.id}`}>{g.members}</Link>
                      </td>
                      <td>
                        <div className="report-actions">
                          <Link className="btn btn-ghost btn-sm" to={`/aksiyonlar/yeni?groups=${g.id}`}>
                            {t("groups.deploy")}
                          </Link>
                          {editable && (
                            <>
                              <button
                                type="button"
                                className="btn btn-ghost btn-sm"
                                onClick={() => setEditing(g.id)}
                              >
                                {t("windows.edit")}
                              </button>
                              <button
                                type="button"
                                className="btn btn-ghost btn-sm"
                                onClick={() => void remove(g)}
                              >
                                {t("windows.delete")}
                              </button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  ),
                )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
