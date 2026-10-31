import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import i18n from "../i18n";
import { MemoryRouter } from "react-router";
import { App } from "../App";
import { AuthProvider } from "../auth/AuthProvider";
import { mockMatchMedia } from "../test/matchMedia";
import { ThemeProvider } from "../theme/ThemeProvider";

function json(status: number, body: unknown) {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }),
  );
}

const me = {
  user: { id: "u1", username: "admin", display_name: "Ayşe Yılmaz", role: "admin", source: "local" },
  permissions: ["machines.read"],
  csrf_token: "csrf-123",
};

function renderApp() {
  return render(
    <MemoryRouter>
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

describe("giriş ekranı", () => {
  it("oturum yoksa Türkçe giriş formunu gösterir", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => json(401, { code: "auth.unauthenticated", message: "" })),
    );
    renderApp();
    expect(await screen.findByRole("heading", { name: "Oturum açın" })).toBeInTheDocument();
    expect(screen.getByLabelText("Kullanıcı adı")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Oturum aç" })).toBeDisabled();
  });

  it("hatalı parolada API hata koduna karşılık gelen mesajı gösterir", async () => {
    const fetchMock = vi.fn((url: string) =>
      url.endsWith("/auth/me")
        ? json(401, { code: "auth.unauthenticated", message: "" })
        : json(401, { code: "auth.invalid_credentials", message: "x" }),
    );
    vi.stubGlobal("fetch", fetchMock);
    renderApp();
    await userEvent.type(await screen.findByLabelText("Kullanıcı adı"), "admin");
    await userEvent.type(screen.getByLabelText("Parola"), "yanlis");
    await userEvent.click(screen.getByRole("button", { name: "Oturum aç" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Kullanıcı adı veya parola hatalı.");
    const [, init] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ username: "admin", password: "yanlis" });
    expect(screen.getByLabelText("Parola")).toHaveValue("");
  });

  it("başarılı girişten sonra gösterge panelini açar ve CSRF token'ını gönderir", async () => {
    const fetchMock = vi.fn((url: string, init?: RequestInit) => {
      if (url.endsWith("/auth/me")) return json(401, { code: "auth.unauthenticated", message: "" });
      if (url.endsWith("/auth/login")) return json(200, me);
      if (url.includes("/machines/summary"))
        return json(200, {
          total: 0,
          online: 0,
          pending: 0,
          with_inventory: 0,
          fully_patched: 0,
          missing_total: 0,
          critical_machines: 0,
          reboot_pending: 0,
          windows: 0,
          macos: 0,
          distinct_apps: 0,
        });
      if (url.includes("/machines")) return json(200, { items: [], total: 0, page: 1, page_size: 8 });
      if (url.endsWith("/server-info"))
        return json(200, { version: "0.1.0", agent_url: "https://ber:52311", ca_fingerprint: "sha256:ab" });
      if (url.endsWith("/auth/logout")) {
        expect((init?.headers as Record<string, string>)["X-CSRF-Token"]).toBe("csrf-123");
        return Promise.resolve(new Response(null, { status: 204 }));
      }
      return json(404, {});
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp();
    await userEvent.type(await screen.findByLabelText("Kullanıcı adı"), "admin");
    await userEvent.type(screen.getByLabelText("Parola"), "dogru-parola");
    await userEvent.click(screen.getByRole("button", { name: "Oturum aç" }));

    expect(await screen.findByRole("heading", { name: "Gösterge Paneli" })).toBeInTheDocument();
    expect(screen.getByText("Hoş geldiniz, Ayşe Yılmaz")).toBeInTheDocument();
    expect(await screen.findByText("sha256:ab")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Çıkış yap" }));
    expect(await screen.findByRole("heading", { name: "Oturum açın" })).toBeInTheDocument();
  });

  it("dil İngilizceye çevrilebilir", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => json(401, { code: "auth.unauthenticated", message: "" })),
    );
    renderApp();
    await userEvent.click(await screen.findByRole("button", { name: "EN" }));
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe("en");
  });
});
