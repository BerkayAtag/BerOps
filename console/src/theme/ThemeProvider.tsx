import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  applyTheme,
  onSystemThemeChange,
  readPreference,
  resolveTheme,
  savePreference,
  type Theme,
  type ThemePreference,
} from "./theme";

interface ThemeContextValue {
  theme: Theme;
  preference: ThemePreference;
  toggle: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [preference, setPreference] = useState<ThemePreference>(readPreference);
  const [theme, setTheme] = useState<Theme>(() => resolveTheme(preference));

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  // Kullanıcı açıkça seçim yapmadıysa işletim sistemi teması değiştiğinde takip edilir.
  useEffect(() => {
    if (preference !== "system") return;
    return onSystemThemeChange(setTheme);
  }, [preference]);

  const toggle = useCallback(() => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    savePreference(next);
    setPreference(next);
    setTheme(next);
  }, [theme]);

  const value = useMemo(() => ({ theme, preference, toggle }), [theme, preference, toggle]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme, ThemeProvider içinde kullanılmalı");
  return ctx;
}
