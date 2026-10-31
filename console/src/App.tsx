import { useTranslation } from "react-i18next";
import { Navigate, Route, Routes } from "react-router";
import { useAuth } from "./auth/AuthProvider";
import { AppShell } from "./components/AppShell";
import { AgentSettingsPage } from "./pages/AgentSettingsPage";
import { HomePage } from "./pages/HomePage";
import { LoginPage } from "./pages/LoginPage";
import { MachineDetailPage } from "./pages/MachineDetailPage";
import { MachinesPage } from "./pages/MachinesPage";

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
      <Routes>
        <Route path="/" element={<HomePage me={state.me} />} />
        <Route path="/makineler" element={<MachinesPage />} />
        <Route path="/makineler/:id" element={<MachineDetailPage />} />
        <Route path="/ayarlar/ajan" element={<AgentSettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppShell>
  );
}
