import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { api, errorKey, type Action } from "../api/client";

// RestartForm, seçili makineler için bildirimli yeniden başlatma aksiyonu oluşturur.
// Kullanıcıya ileti gösterilir ve verilen süre sonunda makine yeniden başlatılır.
export function RestartForm({ machineIds, onCancel }: { machineIds: string[]; onCancel: () => void }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [delay, setDelay] = useState(15);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const a = await api<Action>("/api/v1/actions", {
        method: "POST",
        body: {
          kind: "restart",
          machine_ids: machineIds,
          restart_delay_minutes: delay,
          restart_message: message.trim(),
        },
      });
      navigate(`/aksiyonlar/${a.id}`);
    } catch (err) {
      const invalid = err instanceof Error && "code" in err && err.code === "request.invalid";
      setError(invalid ? err.message : t(errorKey(err), { defaultValue: t("errors.unknown") }));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card card-body stack" onSubmit={(e) => void submit(e)}>
      <h2>{t("restart.title", { count: machineIds.length })}</h2>
      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}
      <div className="form-grid">
        <label>
          {t("restart.delay")}
          <input
            className="input input-sm"
            type="number"
            min={0}
            max={1440}
            value={delay}
            onChange={(e) => setDelay(Number(e.target.value))}
          />
          <span className="hint">{t("restart.delayHint")}</span>
        </label>
        <label className="span-2">
          {t("restart.message")}
          <input
            className="input input-sm"
            maxLength={200}
            placeholder={t("restart.messagePlaceholder")}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
          />
        </label>
      </div>
      <p className="muted small">{t("restart.note")}</p>
      <div className="report-actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={busy}>
          {t("restart.submit")}
        </button>
        <button type="button" className="btn btn-ghost btn-sm" onClick={onCancel}>
          {t("common.cancel")}
        </button>
      </div>
    </form>
  );
}
