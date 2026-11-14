import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router";
import i18n from "../i18n";
import { App } from "../App";
import { AuthProvider } from "../auth/AuthProvider";
import { mockMatchMedia } from "../test/matchMedia";
import { ThemeProvider } from "../theme/ThemeProvider";

function renderAs(role: "admin" | "readonly", permissions: string[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      const body = url.endsWith("/auth/me")
        ? {
            user: { id: "u1", username: "ayse", display_name: "", role, source: "local" },
            permissions,
            csrf_token: "c",
          }
        : {};
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status: url.endsWith("/auth/me") ? 200 : 404,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }),
  );
  return render(
    <MemoryRouter initialEntries={["/hesap"]}>
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

afterEach(() => vi.unstubAllGlobals());

describe("menü", () => {
  it("çıkış başarısızsa oturumu korur ve yeniden denemeye izin verir", async () => {
    renderAs("admin", ["machines.read"]);
    await screen.findByRole("heading", { name: "Hesabım" });
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "internal" }), { status: 500 }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Çıkış yap" }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Hesabım" })).toBeInTheDocument();
    vi.mocked(fetch).mockResolvedValueOnce(new Response(null, { status: 204 }));
    await userEvent.click(screen.getByRole("button", { name: "Çıkış yap" }));
    expect(await screen.findByRole("heading", { name: "Oturum açın" })).toBeInTheDocument();
  });

  it("yönetim sayfalarını yalnızca yetkili kullanıcıya gösterir", async () => {
    renderAs("readonly", ["machines.read", "audit.read"]);
    await screen.findByRole("heading", { name: "Hesabım" });
    expect(screen.getByRole("link", { name: "Denetim Kaydı" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Kullanıcılar" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Active Directory" })).not.toBeInTheDocument();
  });

  it("admin tüm yönetim sayfalarını görür", async () => {
    renderAs("admin", ["machines.read", "audit.read", "users.manage", "ad.configure"]);
    await screen.findByRole("heading", { name: "Hesabım" });
    expect(screen.getByRole("link", { name: "Kullanıcılar" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Active Directory" })).toBeInTheDocument();
  });
});
