import { Fragment, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, errorKey, type Role, type User } from "../api/client";
import { useApi } from "../api/useApi";
import { formatRelative } from "../format";
import { parseScope } from "../scope";

const ROLES: Role[] = ["admin", "technician", "readonly"];

function useError() {
  const { t } = useTranslation();
  const [error, setError] = useState<string | null>(null);
  const fail = (err: unknown) => {
    const invalid = err instanceof Error && "code" in err && err.code === "request.invalid";
    setError(invalid ? err.message : t(errorKey(err), { defaultValue: t("errors.unknown") }));
  };
  return { error, setError, fail };
}

function CreateUserForm({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const [f, setF] = useState({
    username: "",
    display_name: "",
    password: "",
    role: "readonly" as Role,
    scope: "",
  });
  const { error, setError, fail } = useError();
  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api("/api/v1/users", {
        method: "POST",
        body: { ...f, scope_ous: parseScope(f.scope) },
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
          {t("users.field.username")}
          <input
            className="input input-sm"
            required
            value={f.username}
            onChange={(e) => setF({ ...f, username: e.target.value })}
          />
        </label>
        <label>
          {t("users.field.displayName")}
          <input
            className="input input-sm"
            value={f.display_name}
            onChange={(e) => setF({ ...f, display_name: e.target.value })}
          />
        </label>
        <label>
          {t("users.field.password")}
          <input
            className="input input-sm"
            type="password"
            autoComplete="new-password"
            required
            minLength={12}
            value={f.password}
            onChange={(e) => setF({ ...f, password: e.target.value })}
          />
          <span className="hint">{t("users.hint.password")}</span>
        </label>
        <label>
          {t("users.field.role")}
          <select
            className="select select-sm"
            value={f.role}
            onChange={(e) => setF({ ...f, role: e.target.value as Role })}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {t(`roles.${r}`)}
              </option>
            ))}
          </select>
        </label>
      </div>
      {f.role !== "admin" && (
        <label>
          {t("users.field.scope")}
          <textarea
            className="textarea"
            rows={3}
            value={f.scope}
            onChange={(e) => setF({ ...f, scope: e.target.value })}
          />
          <span className="hint">{t("users.hint.scope")}</span>
        </label>
      )}
      <div>
        <button type="submit" className="btn btn-primary btn-sm">
          {t("users.create")}
        </button>
      </div>
    </form>
  );
}

function EditUser({ user, onDone }: { user: User; onDone: () => void }) {
  const { t } = useTranslation();
  const [role, setRole] = useState<Role>(user.role);
  const [scope, setScope] = useState(user.scope_ous.join("\n"));
  const [password, setPassword] = useState("");
  const { error, setError, fail } = useError();
  const isAD = user.source === "ad";

  async function save(body: Record<string, unknown>) {
    setError(null);
    try {
      await api(`/api/v1/users/${user.id}`, { method: "PATCH", body });
      onDone();
    } catch (err) {
      fail(err);
    }
  }

  return (
    <div className="stack">
      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}
      {isAD ? (
        <p className="muted small">{t("users.adManaged")}</p>
      ) : (
        <div className="form-grid">
          <label>
            {t("users.field.role")}
            <select
              className="select select-sm"
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {t(`roles.${r}`)}
                </option>
              ))}
            </select>
          </label>
          <label className="span-2">
            {t("users.field.scope")}
            <textarea
              className="textarea"
              rows={3}
              value={scope}
              onChange={(e) => setScope(e.target.value)}
            />
          </label>
          <div>
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => void save({ role, scope_ous: parseScope(scope) })}
            >
              {t("users.save")}
            </button>
          </div>
        </div>
      )}
      <div className="report-actions">
        {!isAD && (
          <>
            <input
              className="input input-sm"
              type="password"
              autoComplete="new-password"
              placeholder={t("users.newPassword")}
              aria-label={t("users.newPassword")}
              minLength={12}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              disabled={password.length < 12}
              onClick={() => void save({ password })}
            >
              {t("users.resetPassword")}
            </button>
          </>
        )}
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          onClick={() => void save({ disabled: !user.disabled })}
        >
          {user.disabled ? t("users.enable") : t("users.disable")}
        </button>
      </div>
    </div>
  );
}

export function UsersPage() {
  const { t, i18n } = useTranslation();
  const [list, reload] = useApi<{ items: User[] }>("/api/v1/users");
  const [showNew, setShowNew] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  return (
    <div className="page">
      <header className="page-header page-header-row">
        <div>
          <h1>{t("users.title")}</h1>
          <p className="muted">{t("users.subtitle")}</p>
        </div>
        <button type="button" className="btn btn-primary" onClick={() => setShowNew((v) => !v)}>
          {t("users.new")}
        </button>
      </header>
      {notice && (
        <div className="alert alert-info" role="status">
          {notice}
        </div>
      )}
      {list.status === "error" && (
        <div className="alert alert-danger" role="alert">
          {t(list.error, { defaultValue: t("errors.unknown") })}
        </div>
      )}
      {showNew && (
        <section className="card">
          <div className="card-header">
            <h2>{t("users.new")}</h2>
          </div>
          <CreateUserForm
            onDone={() => {
              setShowNew(false);
              setNotice(t("users.created"));
              reload();
            }}
          />
        </section>
      )}
      <section className="card">
        <div className="table-wrap">
          <table className="table" aria-label={t("users.title")}>
            <thead>
              <tr>
                <th>{t("users.col.username")}</th>
                <th>{t("users.col.role")}</th>
                <th>{t("users.col.source")}</th>
                <th>{t("users.col.scope")}</th>
                <th>{t("users.col.lastLogin")}</th>
                <th>{t("users.col.status")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.status === "ok" &&
                list.data.items.map((u) => (
                  <Fragment key={u.id}>
                    <tr>
                      <td>
                        <span className="strong">{u.username}</span>
                        {u.display_name && <span className="muted small"> · {u.display_name}</span>}
                        {u.is_recovery && <span className="tag">{t("users.recovery")}</span>}
                      </td>
                      <td>
                        <span className={`role-badge role-${u.role}`}>{t(`roles.${u.role}`)}</span>
                      </td>
                      <td>
                        <span className="tag">{t(`users.source.${u.source}`)}</span>
                      </td>
                      <td className="small cell-wrap">
                        {u.role === "admin" || u.scope_ous.length === 0 ? (
                          <span className="muted">{t("users.allMachines")}</span>
                        ) : (
                          u.scope_ous.join("; ")
                        )}
                      </td>
                      <td>{formatRelative(u.last_login_at, i18n.language, t("common.never"))}</td>
                      <td>
                        <span className={`pill ${u.disabled ? "pill-danger" : "pill-success"}`}>
                          {u.disabled ? t("users.disabled") : t("users.active")}
                        </span>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm"
                          aria-expanded={editing === u.id}
                          onClick={() => setEditing(editing === u.id ? null : u.id)}
                        >
                          {t("users.edit")}
                        </button>
                      </td>
                    </tr>
                    {editing === u.id && (
                      <tr className="target-output">
                        <td colSpan={7}>
                          <EditUser
                            user={u}
                            onDone={() => {
                              setEditing(null);
                              setNotice(t("users.updated"));
                              reload();
                            }}
                          />
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
