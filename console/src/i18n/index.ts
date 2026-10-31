import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./locales/en.json";
import tr from "./locales/tr.json";

export const LANGUAGES = ["tr", "en"] as const;
export type Language = (typeof LANGUAGES)[number];

const STORAGE_KEY = "ber-lang";

function savedLanguage(): Language {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "tr" || v === "en") return v;
  } catch {
    // Depolama erişilemiyorsa varsayılan dil kullanılır.
  }
  return "tr"; // Türkçe varsayılan dildir; tarayıcı dili esas alınmaz.
}

void i18n.use(initReactI18next).init({
  resources: { tr: { translation: tr }, en: { translation: en } },
  lng: savedLanguage(),
  fallbackLng: "tr",
  interpolation: { escapeValue: false },
  returnNull: false,
});

function syncDocument(lng: string) {
  document.documentElement.lang = lng;
}
syncDocument(i18n.language);

i18n.on("languageChanged", (lng) => {
  syncDocument(lng);
  try {
    localStorage.setItem(STORAGE_KEY, lng);
  } catch {
    // Tercih kaydedilemezse yalnızca bu oturumda geçerli olur.
  }
});

export default i18n;
