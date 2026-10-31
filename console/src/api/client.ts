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

export interface MachineListItem extends Machine {
  ad_ou: string;
  inventory_at: string | null;
  missing_count: number;
  missing_critical_count: number;
  missing_security_count: number;
  app_count: number;
  reboot_pending: boolean;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface FleetSummary {
  total: number;
  online: number;
  pending: number;
  with_inventory: number;
  fully_patched: number;
  missing_total: number;
  critical_machines: number;
  reboot_pending: number;
  windows: number;
  macos: number;
  distinct_apps: number;
}

export interface OSInventory {
  platform: string;
  name: string;
  version: string;
  build: string;
  arch: string;
  manufacturer?: string;
  model?: string;
  serial_number?: string;
  cpu_model?: string;
  cpu_cores?: number;
  memory_bytes?: number;
  domain?: string;
  ad_dn?: string;
  last_boot_at?: string;
  reboot_pending: boolean;
}

export interface InventorySummary {
  os: OSInventory | null;
  collected_at: string;
  received_at: string;
  last_full_at: string | null;
  scan_duration_ms: number;
  missing_scan_source: string;
  missing_scanned_at: string | null;
  scan_errors: string[];
  missing_count: number;
  missing_critical_count: number;
  missing_security_count: number;
  installed_patch_count: number;
  app_count: number;
  reboot_pending: boolean;
}

export interface MachineDetail {
  machine: Machine & {
    ad_ou: string;
    cert_expires_at: string;
    agent_started_at: string | null;
    last_errors: string[];
  };
  online: boolean;
  scan_requested_at: string | null;
  inventory: InventorySummary | null;
}

export interface MissingPatch {
  id: string;
  kb?: string;
  title: string;
  classification?: string;
  severity?: string;
  released_at?: string;
  reboot_required: boolean;
  size_bytes?: number;
  cves?: string[];
  version?: string;
  recommended?: boolean;
  support_url?: string;
}

export interface InstalledPatch {
  id: string;
  title?: string;
  installed_on?: string;
  source: string;
}

export interface InstalledApp {
  name: string;
  version: string;
  publisher?: string;
  install_date?: string;
  install_location?: string;
  source: string;
  identifier?: string;
  arch?: string;
  scope?: string;
}

export interface AgentSettings {
  full_scan_interval_hours: number;
  delta_scan_interval_hours: number;
  scan_cpu_limit_percent: number;
  defer_on_battery: boolean;
  defer_when_user_active: boolean;
  windows_update_source: "online" | "offline";
}

export interface AgentSettingsResponse {
  settings: AgentSettings;
  wsus_cab: { size_bytes: number; modified_at: string } | null;
}
