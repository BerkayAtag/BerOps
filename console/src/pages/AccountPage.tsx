import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, errorKey, type Me } from "../api/client";

export function AccountPage({ me }: { me: Me }) {
  const { t } = useTranslation();
  const [f, setF] = useState({ current: "", next: "", confirm: "" });
  const [notice, setNotice] = useState<{ kind: "info" | "danger"; text: string } | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (f.next !== f.confirm) {
      setNotice({ kind: "danger", text: t("account.mismatch") });
      return;
    }
    try {
      await api("/api/v1/auth/password", {
        method: "POST",
        body: { current_password: f.current, new_password: f.next },
      });
      setF({ current: "", next: "", confirm: "" });
      setNotice({ kind: "info", text: t("account.changed") });
    } catch (err) {
      const invalid = err instanceof Error && "code" in err && err.code === "request.invalid";
      setNotice({
        kind: "danger",
        text: invalid ? err.message : t(errorKey(err), { defaultValue: t("errors.unknown") }),
      });
    }
  }

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>{t("account.title")}</h1>
          <p className="muted">{t("account.subtitle")}</p>
        </div>
      </header>
      <section className="card">
        <dl className="card-body fields">
          <div className="field-row">
            <dt>{t("users.field.username")}</dt>
            <dd>{me.user.username}</dd>
          </div>
          <div className="field-row">
            <dt>{t("account.role")}</dt>
            <dd>
              <span className={`role-badge role-${me.user.role}`}>{t(`roles.${me.user.role}`)}</span>
            </dd>
          </div>
          <div className="field-row">
            <dt>{t("account.source")}</dt>
            <dd>{t(`users.source.${me.user.source}`)}</dd>
          </div>
        </dl>
      </section>
      <section className="card">
        <div className="card-header">
          <h2>{t("account.changePassword")}</h2>
        </div>
        {me.user.source === "ad" ? (
          <p className="card-body muted">{t("account.adNotice")}</p>
        ) : (
          <form className="card-body stack" onSubmit={(e) => void submit(e)}>
            {notice && (
              <div className={`alert alert-${notice.kind}`} role="status">
                {notice.text}
              </div>
            )}
            <div className="form-grid">
              <label>
                {t("account.current")}
                <input
                  className="input input-sm"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={f.current}
                  onChange={(e) => setF({ ...f, current: e.target.value })}
                />
              </label>
              <label>
                {t("account.new")}
                <input
                  className="input input-sm"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={12}
                  value={f.next}
                  onChange={(e) => setF({ ...f, next: e.target.value })}
                />
                <span className="hint">{t("users.hint.password")}</span>
              </label>
              <label>
                {t("account.confirm")}
                <input
                  className="input input-sm"
                  type="password"
                  autoComplete="new-password"
                  required
                  value={f.confirm}
                  onChange={(e) => setF({ ...f, confirm: e.target.value })}
                />
              </label>
            </div>
            <div>
              <button type="submit" className="btn btn-primary btn-sm">
                {t("account.changePassword")}
              </button>
            </div>
          </form>
        )}
      </section>
    </div>
  );
}
