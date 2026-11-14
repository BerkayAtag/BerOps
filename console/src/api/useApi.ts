import { useCallback, useEffect, useState } from "react";
import { api, errorKey } from "./client";

export type Load<T> = { status: "loading" } | { status: "error"; error: string } | { status: "ok"; data: T };

/** GET isteği yapar; path değiştiğinde veya reload çağrıldığında yeniden yükler. */
export function useApi<T>(path: string | null): [Load<T>, () => void] {
  const [result, setResult] = useState<{ path: string; state: Load<T> } | null>(null);
  const [nonce, setNonce] = useState(0);
  useEffect(() => {
    if (path === null) return;
    let cancelled = false;
    api<T>(path)
      .then((data) => !cancelled && setResult({ path, state: { status: "ok", data } }))
      .catch(
        (err: unknown) => !cancelled && setResult({ path, state: { status: "error", error: errorKey(err) } }),
      );
    return () => {
      cancelled = true;
    };
  }, [path, nonce]);
  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return [path !== null && result?.path === path ? result.state : { status: "loading" }, reload];
}
