// Tarih, boyut ve süre biçimlendirme. Dil koduna göre Türkçe veya İngilizce yerel ayar kullanılır.

function locale(lng: string) {
  return lng === "tr" ? "tr-TR" : "en-GB";
}

export function formatDateTime(iso: string | null | undefined, lng: string, fallback = "—") {
  if (!iso) return fallback;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return fallback;
  return new Intl.DateTimeFormat(locale(lng), { dateStyle: "short", timeStyle: "short" }).format(d);
}

export function formatDate(iso: string | null | undefined, lng: string, fallback = "—") {
  if (!iso) return fallback;
  const d = new Date(iso.length === 10 ? iso + "T00:00:00Z" : iso);
  if (Number.isNaN(d.getTime())) return fallback;
  return new Intl.DateTimeFormat(locale(lng), {
    dateStyle: "medium",
    timeZone: iso.length === 10 ? "UTC" : undefined,
  }).format(d);
}

export function formatRelative(iso: string | null | undefined, lng: string, fallback = "—") {
  if (!iso) return fallback;
  const diff = (new Date(iso).getTime() - Date.now()) / 1000;
  const rtf = new Intl.RelativeTimeFormat(locale(lng), { numeric: "auto" });
  const abs = Math.abs(diff);
  if (abs < 60) return rtf.format(Math.round(diff), "second");
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour");
  return rtf.format(Math.round(diff / 86400), "day");
}

export function formatBytes(n: number | null | undefined, lng: string) {
  if (!n) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${new Intl.NumberFormat(locale(lng), { maximumFractionDigits: v < 10 ? 1 : 0 }).format(v)} ${units[i]}`;
}

export function formatNumber(n: number, lng: string) {
  return new Intl.NumberFormat(locale(lng)).format(n);
}

/** Yüzde biçimi dile göre değişir: Türkçede "%50", İngilizcede "50%". */
export function formatPercent(n: number, lng: string) {
  return new Intl.NumberFormat(locale(lng), { style: "percent", maximumFractionDigits: 0 }).format(n / 100);
}
