import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router";
import i18n from "../i18n";
import { App } from "../App";
import { AuthProvider } from "../auth/AuthProvider";
import { mockMatchMedia } from "../test/matchMedia";
import { ThemeProvider } from "../theme/ThemeProvider";

function json(status: number, body: unknown) {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }),
  );
}

const machine = (id: string, hostname: string, extra: Record<string, unknown> = {}) => ({
  id,
  hostname,
  status: "active",
  online: true,
  os_platform: "windows",
  os_name: "Windows 11 Pro",
  os_version: "23H2",
  os_build: "10.0.22631.4460",
  arch: "amd64",
  ip_addresses: ["10.0.0.5"],
  agent_version: "0.2.0",
  ad_ou: "",
  enrolled_at: "2026-10-01T10:00:00Z",
  last_seen_at: new Date().toISOString(),
  inventory_at: "2026-10-30T10:00:00Z",
  missing_count: 3,
  missing_critical_count: 1,
  missing_security_count: 2,
  app_count: 40,
  reboot_pending: false,
  ...extra,
});

function renderAt(path: string, role: "admin" | "readonly", fetchLog: string[]) {
  const me = {
    user: { id: "u1", username: "ayse", display_name: "", role, source: "local" },
    permissions: role === "admin" ? ["machines.read", "machines.manage"] : ["machines.read"],
    csrf_token: "c",
  };
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      fetchLog.push(url);
      if (url.endsWith("/auth/me")) return json(200, me);
      if (url.startsWith("/api/v1/machines?"))
        return json(200, {
          items: [
            machine("00000000-0000-4000-8000-000000000001", "PC-ALFA"),
            machine("00000000-0000-4000-8000-000000000002", "PC-BETA", { inventory_at: null }),
          ],
          total: 2,
          page: 1,
          page_size: 50,
        });
      return json(404, {});
    }),
  );
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ThemeProvider>
        <AuthProvider>
          <App />
        </AuthProvider>
      </ThemeProvider>
    </MemoryRouter>,
  );
}

beforeEach(async () => {
  mockMatchMedia(false);
  await i18n.changeLanguage("tr");
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("makine listesi", () => {
  it("satırları, eksik yama sayılarını ve envanter bekleyen makineyi gösterir", async () => {
    renderAt("/makineler", "admin", []);
    expect(await screen.findByRole("link", { name: "PC-ALFA" })).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Makineler" });
    expect(within(table).getByText("Envanter bekleniyor")).toBeInTheDocument();
    expect(screen.getByText("1–2 / 2")).toBeInTheDocument();
  });

  it("filtre ve sıralama sunucu sorgusuna yansır", async () => {
    const log: string[] = [];
    renderAt("/makineler", "admin", log);
    await screen.findByRole("link", { name: "PC-ALFA" });
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Platform" }), "darwin");
    await userEvent.click(screen.getByRole("button", { name: /Eksik yama/ }));
    const last = log.filter((u) => u.startsWith("/api/v1/machines?")).at(-1)!;
    const q = new URLSearchParams(last.split("?")[1]);
    expect(q.get("platform")).toBe("darwin");
    expect(q.get("sort")).toBe("missing_count");
  });

  it("salt okunur kullanıcıda toplu yeniden tarama devre dışıdır", async () => {
    renderAt("/makineler", "readonly", []);
    await screen.findByRole("link", { name: "PC-ALFA" });
    await userEvent.click(screen.getAllByRole("checkbox", { name: "Satırı seç" })[0]!);
    expect(screen.getByText("1 seçili")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Seçilenleri yeniden tara" })).toBeDisabled();
  });
});
