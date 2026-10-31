import { useTranslation } from "react-i18next";
import { Navigate, Route, Routes } from "react-router";
import { useAuth } from "./auth/AuthProvider";
import { AppShell } from "./components/AppShell";
import { ActionDetailPage } from "./pages/ActionDetailPage";
import { AccountPage } from "./pages/AccountPage";
import { ActionsPage } from "./pages/ActionsPage";
import { AdSettingsPage } from "./pages/AdSettingsPage";
import { AgentSettingsPage } from "./pages/AgentSettingsPage";
import { AuditPage } from "./pages/AuditPage";
import { MaintenanceWindowsPage } from "./pages/MaintenanceWindowsPage";
import { NotificationsPage } from "./pages/NotificationsPage";
import { RelaysPage } from "./pages/RelaysPage";
import { CveSettingsPage } from "./pages/CveSettingsPage";
import { HomePage } from "./pages/HomePage";
import { LoginPage } from "./pages/LoginPage";
import { MachineDetailPage } from "./pages/MachineDetailPage";
import { MachinesPage } from "./pages/MachinesPage";
import { NewActionPage } from "./pages/NewActionPage";
import { PackageDetailPage } from "./pages/PackageDetailPage";
import { PackagesPage } from "./pages/PackagesPage";
import { RemoteSettingsPage } from "./pages/RemoteSettingsPage";
import { ReportsPage } from "./pages/ReportsPage";
import { TransferSettingsPage } from "./pages/TransferSettingsPage";
import { UsersPage } from "./pages/UsersPage";
import { VulnerabilitiesPage } from "./pages/VulnerabilitiesPage";
import { VulnerabilityDetailPage } from "./pages/VulnerabilityDetailPage";

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
        <Route path="/zafiyetler" element={<VulnerabilitiesPage />} />
        <Route path="/zafiyetler/:id" element={<VulnerabilityDetailPage />} />
        <Route path="/raporlar" element={<ReportsPage />} />
        <Route path="/paketler" element={<PackagesPage />} />
        <Route path="/paketler/:id" element={<PackageDetailPage />} />
        <Route path="/aksiyonlar" element={<ActionsPage />} />
        <Route path="/aksiyonlar/yeni" element={<NewActionPage />} />
        <Route path="/aksiyonlar/:id" element={<ActionDetailPage />} />
        <Route path="/ayarlar/aktarim" element={<TransferSettingsPage />} />
        <Route path="/ayarlar/kullanicilar" element={<UsersPage />} />
        <Route path="/ayarlar/ad" element={<AdSettingsPage />} />
        <Route path="/ayarlar/uzaktan" element={<RemoteSettingsPage />} />
        <Route path="/denetim" element={<AuditPage />} />
        <Route path="/hesap" element={<AccountPage me={state.me} />} />
        <Route path="/ayarlar/ajan" element={<AgentSettingsPage />} />
        <Route path="/ayarlar/cve" element={<CveSettingsPage />} />
        <Route path="/ayarlar/relay" element={<RelaysPage />} />
        <Route path="/ayarlar/bakim-pencereleri" element={<MaintenanceWindowsPage />} />
        <Route path="/ayarlar/bildirimler" element={<NotificationsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppShell>
  );
}
