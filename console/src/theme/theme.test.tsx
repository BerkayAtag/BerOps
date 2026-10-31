import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import "../i18n";
import { ThemeToggle } from "../components/ThemeToggle";
import { mockMatchMedia } from "../test/matchMedia";
import { ThemeProvider } from "./ThemeProvider";
import { readPreference, resolveTheme, THEME_STORAGE_KEY } from "./theme";

const theme = () => document.documentElement.getAttribute("data-theme");

afterEach(() => {
  vi.unstubAllGlobals();
  document.documentElement.removeAttribute("data-theme");
});

describe("tema", () => {
  it("kayıtlı tercih yoksa işletim sistemi temasını kullanır", () => {
    mockMatchMedia(true);
    expect(readPreference()).toBe("system");
    expect(resolveTheme("system")).toBe("dark");
    render(<ThemeProvider>x</ThemeProvider>);
    expect(theme()).toBe("dark");
  });

  it("kayıtlı tercih sistem temasından önceliklidir", () => {
    mockMatchMedia(true);
    localStorage.setItem(THEME_STORAGE_KEY, "light");
    render(<ThemeProvider>x</ThemeProvider>);
    expect(theme()).toBe("light");
  });

  it("düğme temayı değiştirir ve tercihi saklar", async () => {
    mockMatchMedia(false);
    render(
      <ThemeProvider>
        <ThemeToggle />
      </ThemeProvider>,
    );
    expect(theme()).toBe("light");
    await userEvent.click(screen.getByRole("button", { name: "Karanlık temaya geç" }));
    expect(theme()).toBe("dark");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
    await userEvent.click(screen.getByRole("button", { name: "Açık temaya geç" }));
    expect(theme()).toBe("light");
  });

  it("açık seçim yapılmadıysa sistem teması değişikliğini izler", () => {
    const mm = mockMatchMedia(false);
    render(<ThemeProvider>x</ThemeProvider>);
    act(() => mm.change(true));
    expect(theme()).toBe("dark");
  });
});
