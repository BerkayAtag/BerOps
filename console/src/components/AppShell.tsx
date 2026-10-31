import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { NavLink } from "react-router";
import type { Me } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { LanguageToggle } from "./LanguageToggle";
import { Logo } from "./Logo";
import { ThemeToggle } from "./ThemeToggle";

const NAV_ITEMS: { key: string; to?: string; end?: boolean }[] = [
  { key: "dashboard", to: "/", end: true },
  { key: "machines", to: "/makineler" },
  { key: "patches" },
  { key: "vulnerabilities" },
  { key: "packages" },
  { key: "actions" },
  { key: "reports" },
  { key: "audit" },
  { key: "settingsAgent", to: "/ayarlar/ajan" },
];

export function AppShell({ me, children }: { me: Me; children: ReactNode }) {
  const { t } = useTranslation();
  const { logout } = useAuth();
  const [navOpen, setNavOpen] = useState(false);
  const name = me.user.display_name || me.user.username;

  return (
    <div className="shell">
      <header className="topbar">
        <button
          type="button"
          className="icon-btn nav-toggle"
          aria-label={t("common.menu")}
          aria-expanded={navOpen}
          onClick={() => setNavOpen((v) => !v)}
        >
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M4 7h16M4 12h16M4 17h16" />
          </svg>
        </button>
        <Logo />
        <div className="topbar-spacer" />
        <LanguageToggle />
        <ThemeToggle />
        <div className="user-chip">
          <span className="user-avatar" aria-hidden="true">
            {name.slice(0, 1).toLocaleUpperCase("tr-TR")}
          </span>
          <span className="user-meta">
            <span className="user-name">{name}</span>
            <span className={`role-badge role-${me.user.role}`}>{t(`roles.${me.user.role}`)}</span>
          </span>
        </div>
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => void logout()}>
          {t("common.logout")}
        </button>
      </header>
      <nav className={`sidebar${navOpen ? " open" : ""}`} aria-label={t("nav.label")}>
        <ul>
          {NAV_ITEMS.map((item) => (
            <li key={item.key}>
              {item.to ? (
                <NavLink
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) => (isActive ? "active" : undefined)}
                  onClick={() => setNavOpen(false)}
                >
                  <span>{t(`nav.${item.key}`)}</span>
                </NavLink>
              ) : (
                <a aria-disabled="true">
                  <span>{t(`nav.${item.key}`)}</span>
                  <span className="soon">{t("common.soon")}</span>
                </a>
              )}
            </li>
          ))}
        </ul>
      </nav>
      <main className="content">{children}</main>
    </div>
  );
}
