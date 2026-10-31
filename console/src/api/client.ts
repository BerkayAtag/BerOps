// Konsol API istemcisi. Oturum çerezi tarayıcı tarafından gönderilir; durum değiştiren
// isteklere oturuma bağlı CSRF token'ı eklenir.

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export async function api<T>(path: string, options: { method?: string; body?: unknown } = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (!SAFE_METHODS.has(method) && csrfToken) headers["X-CSRF-Token"] = csrfToken;

  let resp: Response;
  try {
    resp = await fetch(path, {
      method,
      headers,
      credentials: "same-origin",
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
  } catch {
    throw new ApiError(0, "network", "network");
  }

  if (resp.status === 204) return undefined as T;
  const data: unknown = await resp.json().catch(() => null);
  if (!resp.ok) {
    const err = (data ?? {}) as { code?: string; message?: string };
    throw new ApiError(resp.status, err.code ?? "unknown", err.message ?? resp.statusText);
  }
  return data as T;
}

/** Hata koduna karşılık gelen çeviri anahtarı ("errors.auth.invalid_credentials"). */
export function errorKey(err: unknown): string {
  if (err instanceof ApiError) return `errors.${err.code}`;
  return "errors.unknown";
}

// --- API tipleri ---

export type Role = "admin" | "technician" | "readonly";

export interface Me {
  user: { id: string; username: string; display_name: string; role: Role; source: "local" | "ad" };
  permissions: string[];
  csrf_token: string;
}

export interface Machine {
  id: string;
  hostname: string;
  status: "active" | "pending" | "rejected" | "revoked";
  online: boolean;
  os_platform: "windows" | "darwin";
  os_name: string;
  os_version: string;
  os_build: string;
  arch: string;
  ip_addresses: string[];
  agent_version: string;
  enrolled_at: string;
  last_seen_at: string | null;
}

export interface ServerInfo {
  version: string;
  agent_url: string;
  ca_fingerprint: string;
}
