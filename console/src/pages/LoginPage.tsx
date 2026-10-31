import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { errorKey } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { LanguageToggle } from "../components/LanguageToggle";
import { Logo } from "../components/Logo";
import { ThemeToggle } from "../components/ThemeToggle";

export function LoginPage() {
  const { t } = useTranslation();
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(username.trim(), password);
    } catch (err) {
      setError(errorKey(err));
      setPassword("");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="login">
      <aside className="login-hero">
        <Logo variant="inverse" />
        <div className="login-hero-body">
          <h1>{t("login.heroTitle")}</h1>
          <p>{t("login.heroText")}</p>
          <ul className="login-features">
            {(["feature1", "feature2", "feature3"] as const).map((k) => (
              <li key={k}>
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="m5 12.5 4.5 4.5L19 7.5" />
                </svg>
                {t(`login.${k}`)}
              </li>
            ))}
          </ul>
        </div>
        <p className="login-hero-footer">{t("login.developedBy")}</p>
      </aside>

      <main className="login-main">
        <div className="login-toolbar">
          <LanguageToggle />
          <ThemeToggle />
        </div>

        <div className="login-card">
          <div className="login-card-logo">
            <Logo />
          </div>
          <h2>{t("login.title")}</h2>
          <p className="muted">{t("login.subtitle")}</p>

          <form onSubmit={(e) => void onSubmit(e)} noValidate>
            <label className="field">
              <span>{t("login.username")}</span>
              <input
                className="input"
                name="username"
                autoComplete="username"
                autoCapitalize="none"
                spellCheck={false}
                placeholder={t("login.usernamePlaceholder")}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                autoFocus
              />
            </label>

            <label className="field">
              <span>{t("login.password")}</span>
              <span className="input-with-action">
                <input
                  className="input"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
                <button
                  type="button"
                  className="input-action"
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label={showPassword ? t("login.hidePassword") : t("login.showPassword")}
                  aria-pressed={showPassword}
                >
                  {showPassword ? (
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M3 3l18 18M10.6 5.2A9.8 9.8 0 0 1 12 5c5 0 9 4.5 10 7-.4 1-1.3 2.4-2.6 3.8M6.2 6.6C4.2 8 2.6 10.1 2 12c1 2.5 5 7 10 7 1.7 0 3.3-.5 4.6-1.3M9.9 9.9a3 3 0 0 0 4.2 4.2" />
                    </svg>
                  ) : (
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M2 12c1-2.5 5-7 10-7s9 4.5 10 7c-1 2.5-5 7-10 7S3 14.5 2 12Z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  )}
                </button>
              </span>
            </label>

            {error && (
              <div className="alert alert-danger" role="alert">
                {t(error, { defaultValue: t("errors.unknown") })}
              </div>
            )}

            <button
              type="submit"
              className="btn btn-primary btn-block"
              disabled={submitting || !username.trim() || !password}
            >
              {submitting ? t("login.submitting") : t("login.submit")}
            </button>
          </form>
        </div>

        <footer className="login-footer">
          {t("app.name")} · {t("login.developedBy")}
        </footer>
      </main>
    </div>
  );
}
