import { useTranslation } from "react-i18next";
import { useAuth } from "./auth/AuthProvider";
import { AppShell } from "./components/AppShell";
import { HomePage } from "./pages/HomePage";
import { LoginPage } from "./pages/LoginPage";

// Aşama 1'de tek sayfa var; sonraki aşamalarda sayfalar react-router ile eklenecek.
export function App() {
  const { state } = useAuth();
  const { t } = useTranslation();

  if (state.status === "loading") {
    return (
      <div className="splash" role="status">
        {t("common.loading")}
      </div>
    );
  }
  if (state.status === "anonymous") return <LoginPage />;
  return (
    <AppShell me={state.me}>
      <HomePage me={state.me} />
    </AppShell>
  );
}
