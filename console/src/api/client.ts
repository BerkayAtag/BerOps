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
  vuln_count: number;
  kev_count: number;
  max_risk: number;
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
  risk: MachineRisk | null;
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

// --- Aşama 3: CVE ve raporlar ---

/** NVD ölçeğindeki önem derecesi. */
export type CvssSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE" | "";

export interface MachineRisk {
  vuln_count: number;
  critical_count: number;
  high_count: number;
  kev_count: number;
  max_risk: number;
  computed_at: string;
}

export interface VulnListItem {
  cve_id: string;
  title: string;
  severity: CvssSeverity;
  cvss_score: number | null;
  epss: number | null;
  epss_percentile: number | null;
  kev: boolean;
  kev_due: string | null;
  ransomware: boolean;
  exploited: boolean;
  published_at: string | null;
  affected_machines: number;
  risk_score: number;
  os: boolean;
  app: boolean;
}

export interface AffectedMachine {
  machine_id: string;
  hostname: string;
  os_platform: "windows" | "darwin";
  os_name: string;
  os_build: string;
  sources: string[];
  refs: string[];
  fixed_by: string[];
  first_seen_at: string;
}

export interface CVEDetail {
  cve_id: string;
  known: boolean;
  source: string;
  title: string;
  description: string;
  published_at: string | null;
  modified_at: string | null;
  cvss_score: number | null;
  cvss_vector: string;
  cvss_version: string;
  severity: CvssSeverity;
  cwes: string[];
  references: string[];
  exploited: boolean;
  epss: number | null;
  epss_percentile: number | null;
  kev: {
    name: string;
    date_added: string;
    due_date: string | null;
    ransomware: boolean;
    required_action: string;
  } | null;
  fixes: string[];
  affected: AffectedMachine[];
  risk_score: number;
}

export interface MachineVuln {
  cve_id: string;
  title: string;
  severity: CvssSeverity;
  cvss_score: number | null;
  epss: number | null;
  kev: boolean;
  exploited: boolean;
  sources: string[];
  refs: string[];
  fixed_by: string[];
  risk_score: number;
  first_seen_at: string;
  published_at: string | null;
}

export interface ComplianceSample {
  day: string;
  machines: number;
  with_inventory: number;
  fully_patched: number;
  critical_machines: number;
  kev_machines: number;
  vuln_total: number;
  avg_risk: number;
}

export interface RiskSummary {
  distinct_cves: number;
  affected_machines: number;
  kev_cves: number;
  kev_machines: number;
  urgent_cves: number;
  avg_machine_risk: number;
  by_severity: Record<string, number>;
  top_cves: VulnListItem[];
  top_machines: {
    id: string;
    hostname: string;
    os_platform: "windows" | "darwin";
    vuln_count: number;
    critical_count: number;
    kev_count: number;
    max_risk: number;
  }[];
  trend: ComplianceSample[];
}

export interface FeedStatus {
  feed: "nvd" | "msrc" | "kev" | "epss";
  last_attempt_at: string | null;
  last_success_at: string | null;
  item_count: number;
  duration_ms: number;
  last_error: string;
}

export interface CVEStatus {
  enabled: boolean;
  offline: boolean;
  running: boolean;
  sync_interval_hours: number;
  nvd_api_key: boolean;
  msrc_months: number;
  feeds: FeedStatus[];
  tracked_products: number;
}

export interface ProductRule {
  id: string;
  name?: string;
  publisher?: string;
  identifier?: string;
  os?: string;
  part?: string;
  vendor: string;
  product: string;
  builtin: boolean;
}
