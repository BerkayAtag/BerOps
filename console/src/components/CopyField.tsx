import { useState } from "react";
import { useTranslation } from "react-i18next";

export function CopyField({ label, value }: { label: string; value: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Pano erişimi yoksa kullanıcı metni elle seçebilir.
    }
  }

  return (
    <div className="copy-field">
      <span className="copy-field-label">{label}</span>
      <div className="copy-field-row">
        <code>{value}</code>
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => void copy()}>
          {copied ? t("common.copied") : t("common.copy")}
        </button>
      </div>
    </div>
  );
}
