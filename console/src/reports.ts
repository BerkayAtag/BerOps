// Rapor indirme adresleri. Raporlar GET ile ve oturum çereziyle indirilir; dil ve saat dilimi
// kullanıcının tarayıcısından alınır.

export type ReportType = "compliance" | "vulnerabilities" | "missing-patches" | "apps";
export type ReportFormat = "pdf" | "xlsx" | "csv";

export function reportUrl(
  type: ReportType,
  format: ReportFormat,
  lang: string,
  filters: Record<string, string> = {},
) {
  const q = new URLSearchParams({ format, lang: lang === "en" ? "en" : "tr" });
  try {
    q.set("tz", Intl.DateTimeFormat().resolvedOptions().timeZone);
  } catch {
    // Saat dilimi alınamazsa sunucu UTC kullanır.
  }
  for (const [k, v] of Object.entries(filters)) if (v) q.set(k, v);
  return `/api/v1/reports/${type}?${q}`;
}
