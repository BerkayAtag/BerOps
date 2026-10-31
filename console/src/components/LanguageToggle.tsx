import { useTranslation } from "react-i18next";
import { LANGUAGES } from "../i18n";

export function LanguageToggle() {
  const { t, i18n } = useTranslation();
  return (
    <div className="segmented" role="group" aria-label={t("common.language")}>
      {LANGUAGES.map((lng) => (
        <button
          key={lng}
          type="button"
          aria-pressed={i18n.language === lng}
          onClick={() => void i18n.changeLanguage(lng)}
        >
          {lng.toUpperCase()}
        </button>
      ))}
    </div>
  );
}
