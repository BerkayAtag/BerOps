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

// --- Aşama 4: paketler ve aksiyonlar ---

export type Installer = "msi" | "exe" | "pkg" | "dmg" | "file";
export type Shell = "cmd" | "powershell" | "sh" | "zsh";

export interface Package {
  id: string;
  name: string;
  version: string;
  publisher: string;
  platform: "windows" | "darwin";
  description: string;
  installer: Installer;
  install_command: string;
  shell: Shell;
  success_codes: number[];
  detect_name: string;
  file_name: string;
  file_size: number;
  file_sha256: string;
  created_at: string;
}

export interface PackageDetail extends Package {
  outdated: { machine_id: string; hostname: string; name: string; version: string }[];
  up_to_date: number;
}

export type ActionStatus = "pending_approval" | "active" | "completed" | "cancelled" | "rejected";
export type TargetStatus =
  "pending" | "downloading" | "running" | "succeeded" | "failed" | "cancelled" | "expired";

export interface Action {
  id: string;
  name: string;
  kind: "deploy_package" | "run_command" | "deploy_patch" | "restart" | "collect_logs";
  package_id: string | null;
  package_name: string;
  package_version: string;
  shell: Shell | "";
  command: string;
  timeout_seconds: number;
  bandwidth_kbps: number;
  retry_count: number;
  retry_delay_minutes: number;
  status: ActionStatus;
  target_count: number;
  created_by: string | null;
  created_by_name: string;
  created_at: string;
  expires_at: string;
  approved_at: string | null;
  completed_at: string | null;
  counts: Partial<Record<TargetStatus, number>>;
  respect_windows: boolean;
  rollout: Rollout | null;
  paused_reason: string;
  released_stages: number;
  patches: string[];
  not_before: string | null;
}

export interface Rollout {
  stages: { percent: number; delay_hours: number }[];
  min_success_percent: number;
}

export interface ActionTarget {
  machine_id: string;
  hostname: string;
  os_platform: "windows" | "darwin";
  status: TargetStatus;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  error: string;
  started_at: string | null;
  finished_at: string | null;
  updated_at: string;
  stage: number;
  released: boolean;
  reboot_required: boolean;
  attempts: number;
  next_attempt_at: string | null;
}

export interface RateProfile {
  name: string;
  weekdays: number[];
  start_minute: number;
  end_minute: number;
  kbps: number;
}

export interface TransferSettings {
  per_client_kbps: number;
  max_upload_mb: number;
  command_approval: boolean;
  default_expiry_hours: number;
  total_kbps: number;
  profiles: RateProfile[];
}

/** Çok parçalı dosya yükler; yükleme ilerlemesi için XMLHttpRequest kullanılır. */
export function apiUpload<T>(
  path: string,
  form: FormData,
  onProgress?: (fraction: number) => void,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", path);
    xhr.withCredentials = true;
    xhr.setRequestHeader("Accept", "application/json");
    if (csrfToken) xhr.setRequestHeader("X-CSRF-Token", csrfToken);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total);
    };
    xhr.onerror = () => reject(new ApiError(0, "network", "network"));
    xhr.onload = () => {
      let data: unknown = null;
      try {
        data = JSON.parse(xhr.responseText);
      } catch {
        // gövde JSON değil
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(data as T);
        return;
      }
      const err = (data ?? {}) as { code?: string; message?: string };
      reject(new ApiError(xhr.status, err.code ?? "unknown", err.message ?? xhr.statusText));
    };
    xhr.send(form);
  });
}

// --- Aşama 5: kullanıcılar, AD, denetim ---

export interface User {
  id: string;
  username: string;
  display_name: string;
  email: string;
  source: "local" | "ad";
  role: Role;
  is_recovery: boolean;
  disabled: boolean;
  scope_ous: string[];
  ad_dn: string;
  created_at: string;
  last_login_at: string | null;
}

export interface ADSettings {
  enabled: boolean;
  url: string;
  base_dn: string;
  bind_dn: string;
  has_password: boolean;
  user_attr: string;
  user_filter: string;
  ca_cert_pem: string;
  timeout_seconds: number;
  computers_base_dn: string;
}

export interface ADMapping {
  id: string;
  group_dn: string;
  role: Role;
  scope_ous: string[];
}

export interface ADTestResult {
  ok: boolean;
  message: string;
  user?: { dn: string; username: string; display_name: string; email: string; groups: string[] };
  role?: Role;
  scope_ous?: string[];
}

export interface ADComputer {
  name: string;
  dns_host_name: string;
  dn: string;
  ou: string;
  operating_system: string;
  last_logon: string | null;
  disabled: boolean;
  machine_id: string | null;
}

export interface AuditEntry {
  id: number;
  occurred_at: string;
  actor_type: "user" | "agent" | "system" | "api_key";
  actor_id: string;
  actor_name: string;
  action: string;
  target_type: string;
  target_id: string;
  params: Record<string, unknown>;
  result: "success" | "failure" | "denied";
  detail: string;
  source_ip: string;
}

// --- Aşama 6: uzaktan yönetim ---

export interface RemoteFlags {
  performance: boolean;
  services: boolean;
  registry_read: boolean;
  registry_write: boolean;
}

export interface RemoteStatus {
  enabled: boolean;
  flags: RemoteFlags;
  active: boolean;
  connected: boolean;
  until: string | null;
  platform: "windows" | "darwin";
}

export interface PerfSnapshot {
  collected_at: string;
  cpu_percent: number;
  cpu_cores: number;
  mem_total: number;
  mem_used: number;
  swap_total: number;
  swap_used: number;
  uptime_seconds: number;
  disks: { mount: string; fs_type: string; total: number; used: number }[];
  processes: { pid: number; name: string; user?: string; cpu_percent: number; rss: number }[];
}

export interface ServiceInfo {
  name: string;
  display_name?: string;
  state: "running" | "stopped" | "starting" | "stopping" | "paused" | "unknown";
  start_type?: string;
  pid?: number;
}

export interface RegistryValue {
  name: string;
  type: string;
  data: string;
}

export interface RegistryKey {
  path: string;
  subkeys: string[];
  values: RegistryValue[];
  truncated?: boolean;
}

export type GroupField =
  | "platform"
  | "os_name"
  | "os_build"
  | "hostname"
  | "ad_ou"
  | "tag"
  | "app"
  | "missing_patch"
  | "agent_version"
  | "risk";

export interface GroupCondition {
  field: GroupField;
  op: string;
  value: string;
  name?: string;
}

export interface GroupRule {
  match: "all" | "any";
  conditions: GroupCondition[];
}

export interface Group {
  id: string;
  name: string;
  description: string;
  kind: "static" | "dynamic";
  rule: GroupRule | null;
  created_at: string;
  members: number;
}

export interface GroupsResponse {
  items: Group[];
  tags: { tag: string; machines: number }[];
}
