import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, ApiError, setCsrfToken, type Me } from "../api/client";

type AuthState = { status: "loading" } | { status: "anonymous" } | { status: "authenticated"; me: Me };

interface AuthContextValue {
  state: AuthState;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  /** Arayüzde düğmeleri etkinleştirmek için. Asıl yetki kontrolü sunucu tarafındadır. */
  can: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: "loading" });

  const accept = useCallback((me: Me) => {
    setCsrfToken(me.csrf_token);
    setState({ status: "authenticated", me });
  }, []);

  useEffect(() => {
    let cancelled = false;
    api<Me>("/api/v1/auth/me")
      .then((me) => !cancelled && accept(me))
      .catch(() => !cancelled && setState({ status: "anonymous" }));
    return () => {
      cancelled = true;
    };
  }, [accept]);

  const login = useCallback(
    async (username: string, password: string) => {
      const me = await api<Me>("/api/v1/auth/login", { method: "POST", body: { username, password } });
      accept(me);
    },
    [accept],
  );

  const logout = useCallback(async () => {
    try {
      await api("/api/v1/auth/logout", { method: "POST" });
    } catch (err) {
      // Oturum zaten geçersizse yerel durumu yine de temizle.
      if (!(err instanceof ApiError)) throw err;
    }
    setCsrfToken(null);
    setState({ status: "anonymous" });
  }, []);

  const can = useCallback(
    (permission: string) => state.status === "authenticated" && state.me.permissions.includes(permission),
    [state],
  );

  const value = useMemo(() => ({ state, login, logout, can }), [state, login, logout, can]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth, AuthProvider içinde kullanılmalı");
  return ctx;
}
