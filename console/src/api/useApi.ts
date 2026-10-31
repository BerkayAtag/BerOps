import { useCallback, useEffect, useState } from "react";
import { api, errorKey } from "./client";

export type Load<T> = { status: "loading" } | { status: "error"; error: string } | { status: "ok"; data: T };

/** GET isteği yapar; path değiştiğinde veya reload çağrıldığında yeniden yükler. */
export function useApi<T>(path: string | null): [Load<T>, () => void] {
  const [state, setState] = useState<Load<T>>({ status: "loading" });
  const [nonce, setNonce] = useState(0);
  useEffect(() => {
    if (path === null) return;
    let cancelled = false;
    api<T>(path)
      .then((data) => !cancelled && setState({ status: "ok", data }))
      .catch((err: unknown) => !cancelled && setState({ status: "error", error: errorKey(err) }));
    return () => {
      cancelled = true;
    };
  }, [path, nonce]);
  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return [state, reload];
}
