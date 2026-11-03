import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, errorKey } from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";
import { formatDateTime } from "../format";

type Protection = { enabled: boolean; updated_at: string | null };

// UninstallProtection, ajanların kaldırılmasını bir koda bağlayan ayarı yönetir. Kod sunucuya
// yalnızca kaydederken gönderilir; sunucu ve ajanlar kodun özetini saklar.
export function UninstallProtection() {
  const { t, i18n } = useTranslation();
  const { can } = useAuth();
  const [resp, reload] = useApi<Protection>("/api/v1/settings/agent-protection");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ kind: "info" | "danger"; text: string } | null>(null);
  const editable = can("agents.manage");
  if (resp.status !== "ok") return null;
  const enabled = resp.data.enabled;

  async function save(next: boolean, e?: FormEvent) {
    e?.preventDefault();
    if (!next && !window.confirm(t("protection.confirmDisable"))) return;
    setBusy(true);
    setNotice(null);
    try {
      await api("/api/v1/settings/agent-protection", { method: "PUT", body: { enabled: next, code } });
      setCode("");
      setNotice({ kind: "info", text: t(next ? "protection.saved" : "protection.disabled") });
      reload();
    } catch (err) {
      const invalid = err instanceof Error && "code" in err && err.code === "request.invalid";
      setNotice({
        kind: "danger",
        text: invalid ? err.message : t(errorKey(err), { defaultValue: t("errors.unknown") }),
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card card-body stack" onSubmit={(e) => void save(true, e)}>
      <div>
        <h2>{t("protection.title")}</h2>
        <p className="muted small">{t("protection.subtitle")}</p>
      </div>
      <p>
        <span className={`pill ${enabled ? "pill-success" : "pill-muted"}`}>
          {t(enabled ? "protection.on" : "protection.off")}
        </span>
        {resp.data.updated_at && (
          <span className="muted small">
            {" "}
            {t("protection.updatedAt", { time: formatDateTime(resp.data.updated_at, i18n.language) })}
          </span>
        )}
      </p>
      <label>
        {t(enabled ? "protection.newCode" : "protection.code")}
        <input
          className="input input-sm"
          type="password"
          autoComplete="new-password"
          minLength={12}
          maxLength={128}
          required={!enabled}
          disabled={!editable}
          value={code}
          onChange={(e) => setCode(e.target.value)}
        />
        <span className="hint">{t("protection.codeHint")}</span>
      </label>
      <pre className="output-block">
        <code>{`msiexec /x BerOps-Agent-x64.msi /qn UNINSTALLCODE=…\nsudo BEROPS_UNINSTALL_CODE=… berops-agent-uninstall`}</code>
      </pre>
      {notice && (
        <div className={`alert alert-${notice.kind}`} role="status">
          {notice.text}
        </div>
      )}
      <div className="form-actions">
        <button
          type="submit"
          className="btn btn-primary"
          disabled={!editable || busy || (enabled && code === "")}
          title={editable ? undefined : t("common.noPermission")}
        >
          {t(enabled ? "protection.changeCode" : "protection.enable")}
        </button>
        {enabled && (
          <button
            type="button"
            className="btn btn-ghost"
            disabled={!editable || busy}
            onClick={() => void save(false)}
          >
            {t("protection.disable")}
          </button>
        )}
      </div>
    </form>
  );
}
