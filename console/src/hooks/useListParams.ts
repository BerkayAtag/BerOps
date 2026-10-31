import { useSearchParams } from "react-router";

/** Arama, filtre, sıralama ve sayfa durumunu adres çubuğunda tutar (bağlantı paylaşılabilir). */
export function useListParams() {
  const [params, setParams] = useSearchParams();
  const get = (k: string, d = "") => params.get(k) ?? d;
  const update = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v === null || v === "") next.delete(k);
      else next.set(k, v);
    }
    setParams(next, { replace: true });
  };
  return { get, update };
}
