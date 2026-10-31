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

const vuln = (id: string, extra: Record<string, unknown> = {}) => ({
  cve_id: id,
  title: "Uzaktan kod çalıştırma",
  severity: "CRITICAL",
  cvss_score: 9.8,
  epss: 0.42,
  epss_percentile: 0.97,
  kev: false,
  kev_due: null,
  ransomware: false,
  exploited: false,
  published_at: "2026-10-01T00:00:00Z",
  affected_machines: 12,
  risk_score: 69.3,
  os: true,
  app: false,
  ...extra,
});

function renderAt(path: string, fetchLog: string[]) {
  const me = {
    user: { id: "u1", username: "ayse", display_name: "", role: "readonly", source: "local" },
    permissions: ["machines.read", "reports.read", "reports.export"],
    csrf_token: "c",
  };
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      fetchLog.push(url);
      if (url.endsWith("/auth/me")) return json(200, me);
      if (url.startsWith("/api/v1/vulnerabilities?"))
        return json(200, {
          items: [
            vuln("CVE-2026-0001", { kev: true, ransomware: true, risk_score: 96 }),
            vuln("CVE-2026-0002", { severity: "MEDIUM", cvss_score: 5.3, epss: null, app: true, os: false }),
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

describe("güvenlik açıkları", () => {
  it("risk, KEV ve önem bilgisini gösterir", async () => {
    renderAt("/zafiyetler", []);
    const link = await screen.findByRole("link", { name: "CVE-2026-0001" });
    const row = link.closest("tr")!;
    expect(within(row).getByText("KEV · Fidye yazılımı")).toBeInTheDocument();
    expect(within(row).getByText("Kritik")).toBeInTheDocument();
    expect(within(row).getByText("96")).toBeInTheDocument();
    const second = screen.getByRole("link", { name: "CVE-2026-0002" }).closest("tr")!;
    expect(within(second).getByText("Orta")).toBeInTheDocument();
    expect(within(second).getByText("Uygulama")).toBeInTheDocument();
  });

  it("KEV filtresi sunucu sorgusuna ve dışa aktarma bağlantısına yansır", async () => {
    const log: string[] = [];
    renderAt("/zafiyetler", log);
    await screen.findByRole("link", { name: "CVE-2026-0001" });
    await userEvent.click(screen.getByRole("checkbox", { name: /Yalnızca aktif istismar/ }));
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Önem" }), "CRITICAL");
    const last = log.filter((u) => u.startsWith("/api/v1/vulnerabilities?")).at(-1)!;
    const q = new URLSearchParams(last.split("?")[1]);
    expect(q.get("kev")).toBe("true");
    expect(q.get("severity")).toBe("CRITICAL");
    const excel = screen.getByRole("link", { name: "Excel" });
    const href = new URL(excel.getAttribute("href")!, "https://x");
    expect(href.pathname).toBe("/api/v1/reports/vulnerabilities");
    expect(href.searchParams.get("format")).toBe("xlsx");
    expect(href.searchParams.get("kev")).toBe("true");
    expect(href.searchParams.get("lang")).toBe("tr");
  });
});

describe("raporlar", () => {
  it("her rapor için üç biçimde indirme bağlantısı sunar", async () => {
    renderAt("/raporlar", []);
    await screen.findByRole("heading", { name: "Raporlar" });
    const pdfs = screen.getAllByRole("link", { name: "PDF" });
    expect(pdfs).toHaveLength(4);
    expect(pdfs.map((a) => new URL(a.getAttribute("href")!, "https://x").pathname)).toEqual([
      "/api/v1/reports/compliance",
      "/api/v1/reports/vulnerabilities",
      "/api/v1/reports/missing-patches",
      "/api/v1/reports/apps",
    ]);
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Rapor dili" }), "en");
    expect(new URL(pdfs[0]!.getAttribute("href")!, "https://x").searchParams.get("lang")).toBe("en");
  });
});
