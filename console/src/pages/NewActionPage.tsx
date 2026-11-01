import { useEffect, useMemo, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useSearchParams } from "react-router";
import {
  api,
  errorKey,
  type Action,
  type GroupsResponse,
  type MachineListItem,
  type Package,
  type Page,
  type Shell,
  type TransferSettings,
} from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";
import { PlatformIcon } from "../components/Badges";
import { ROLLOUT_PRESETS, type RolloutPreset } from "../rollout";

type Kind = "deploy_package" | "run_command";
type Target = { id: string; hostname: string; os_platform: "windows" | "darwin" };

function MachinePicker({ selected, onAdd }: { selected: Target[]; onAdd: (m: Target) => void }) {
  const { t } = useTranslation();
  const [q, setQ] = useState("");
  const [debounced, setDebounced] = useState("");
  useEffect(() => {
    const h = window.setTimeout(() => setDebounced(q.trim()), 250);
    return () => window.clearTimeout(h);
  }, [q]);
  const [res] = useApi<Page<MachineListItem>>(
    debounced
      ? `/api/v1/machines?${new URLSearchParams({ q: debounced, status: "active", page_size: "20" })}`
      : null,
  );
  const items =
    debounced && res.status === "ok"
      ? res.data.items.filter((m) => !selected.some((s) => s.id === m.id))
      : [];
  return (
    <div>
      <input
        className="input input-sm"
        type="search"
        placeholder={t("actions.wizard.searchMachines")}
        aria-label={t("actions.wizard.searchMachines")}
        value={q}
        onChange={(e) => setQ(e.target.value)}
      />
      {items.length > 0 && (
        <ul className="picker-results">
          {items.map((m) => (
            <li key={m.id}>
              <button type="button" onClick={() => onAdd(m)}>
                <PlatformIcon platform={m.os_platform} />
                <span className="strong">{m.hostname}</span>
                <span className="muted small">{m.os_name}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function NewActionPage() {
  const { t } = useTranslation();
  const { can } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const canPkg = can("actions.deploy_package");
  const canCmd = can("actions.run_command");
  const initialKind = (params.get("kind") as Kind) ?? (canPkg ? "deploy_package" : "run_command");
  const [kind, setKind] = useState<Kind>(
    initialKind === "run_command" && canCmd ? "run_command" : "deploy_package",
  );
  const [packageId, setPackageId] = useState(params.get("package") ?? "");
  const [shell, setShell] = useState<Shell>("powershell");
  const [command, setCommand] = useState("");
  const [name, setName] = useState("");
  const [timeout, setTimeoutSec] = useState(3600);
  const [bandwidth, setBandwidth] = useState(0);
  const [expires, setExpires] = useState(0);
  const [targets, setTargets] = useState<Target[]>([]);
  const [respectWindows, setRespectWindows] = useState(false);
  const [startAt, setStartAt] = useState("");
  const [groupIds, setGroupIds] = useState<string[]>(() =>
    (params.get("groups") ?? "").split(",").filter(Boolean),
  );
  const [allMachines, setAllMachines] = useState(false);
  const [retryCount, setRetryCount] = useState(0);
  const [retryDelay, setRetryDelay] = useState(30);
  const [groups] = useApi<GroupsResponse>("/api/v1/groups");
  const [rolloutPreset, setRolloutPreset] = useState<RolloutPreset>("none");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [packages] = useApi<{ items: Package[] }>("/api/v1/packages");
  const [settings] = useApi<TransferSettings>("/api/v1/settings/transfer");
  const preset = params.get("machines");
  const [presetList] = useApi<Page<MachineListItem>>(
    preset ? `/api/v1/machines?page_size=500&status=active` : null,
  );
  useEffect(() => {
    if (!preset || presetList.status !== "ok") return;
    const ids = new Set(preset.split(","));
    // Ön seçili makineler yalnızca bir kez eklenir; kullanıcı sonra listeyi değiştirebilir.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setTargets(presetList.data.items.filter((m) => ids.has(m.id)));
  }, [preset, presetList]);

  const pkg = useMemo(
    () => (packages.status === "ok" ? packages.data.items.find((p) => p.id === packageId) : undefined),
    [packages, packageId],
  );
  const platforms = new Set(targets.map((m) => m.os_platform));
  const mismatch = kind === "deploy_package" && pkg && targets.some((m) => m.os_platform !== pkg.platform);
  const shellOptions: Shell[] =
    platforms.size === 1 && platforms.has("darwin") ? ["zsh", "sh"] : ["powershell", "cmd"];
  const effectiveShell = shellOptions.includes(shell) ? shell : shellOptions[0]!;
  const limit = settings.status === "ok" ? settings.data.per_client_kbps : 0;
  const allowed = kind === "deploy_package" ? canPkg : canCmd;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const body: Record<string, unknown> = {
        kind,
        name: name.trim(),
        machine_ids: targets.map((m) => m.id),
        group_ids: groupIds,
        all_machines: allMachines,
        timeout_seconds: timeout,
      };
      if (retryCount > 0) Object.assign(body, { retry_count: retryCount, retry_delay_minutes: retryDelay });
      if (bandwidth > 0) body.bandwidth_kbps = bandwidth;
      if (expires > 0) body.expires_hours = expires;
      if (kind === "deploy_package") body.package_id = packageId;
      else Object.assign(body, { shell: effectiveShell, command });
      if (respectWindows) body.respect_windows = true;
      // datetime-local yerel saattir; sunucuya ISO (UTC) olarak gönderilir.
      if (startAt) body.not_before = new Date(startAt).toISOString();
      if (rolloutPreset !== "none") body.rollout = ROLLOUT_PRESETS[rolloutPreset];
      const a = await api<Action>("/api/v1/actions", { method: "POST", body });
      navigate(`/aksiyonlar/${a.id}`);
    } catch (err) {
      const invalid = err instanceof Error && "code" in err && err.code === "request.invalid";
      setError(invalid ? err.message : t(errorKey(err), { defaultValue: t("errors.unknown") }));
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <Link to="/aksiyonlar" className="back-link">
        ← {t("actions.title")}
      </Link>
      <header className="page-header">
        <h1>{t("actions.wizard.title")}</h1>
      </header>
      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}
      <form className="stack" onSubmit={(e) => void submit(e)}>
        <section className="card">
          <div className="card-header">
            <h2>{t("actions.wizard.kind")}</h2>
          </div>
          <div className="card-body stack">
            <div className="choice-row" role="radiogroup">
              {(["deploy_package", "run_command"] as const).map((k) => {
                const ok = k === "deploy_package" ? canPkg : canCmd;
                return (
                  <label
                    key={k}
                    className={`choice${kind === k ? " active" : ""}`}
                    aria-disabled={!ok}
                    title={ok ? undefined : t("actions.wizard.noPermission")}
                  >
                    <input
                      type="radio"
                      name="kind"
                      value={k}
                      checked={kind === k}
                      disabled={!ok}
                      onChange={() => setKind(k)}
                    />
                    {t(`actions.kind.${k}`)}
                  </label>
                );
              })}
            </div>
            {kind === "deploy_package" ? (
              <label className="field-inline">
                <span className="muted small">{t("actions.wizard.package")}</span>
                <select
                  className="select"
                  required
                  value={packageId}
                  onChange={(e) => setPackageId(e.target.value)}
                >
                  <option value="">{t("actions.wizard.pickPackage")}</option>
                  {packages.status === "ok" &&
                    packages.data.items.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name} {p.version} ({t(`machines.platform.${p.platform}`)})
                      </option>
                    ))}
                </select>
              </label>
            ) : (
              <>
                <label className="field-inline">
                  <span className="muted small">{t("actions.wizard.shell")}</span>
                  <select
                    className="select select-sm"
                    value={effectiveShell}
                    onChange={(e) => setShell(e.target.value as Shell)}
                  >
                    {shellOptions.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  <span className="muted small">{t("actions.wizard.command")}</span>
                  <textarea
                    className="textarea"
                    required
                    maxLength={32768}
                    value={command}
                    spellCheck={false}
                    onChange={(e) => setCommand(e.target.value)}
                  />
                  <span className="hint">{t("actions.wizard.commandHint")}</span>
                </label>
                {settings.status === "ok" && settings.data.command_approval && (
                  <div className="alert alert-info">{t("actions.wizard.approvalNote")}</div>
                )}
              </>
            )}
          </div>
        </section>

        <section className="card">
          <div className="card-header">
            <h2>{t("actions.wizard.targets", { count: targets.length })}</h2>
          </div>
          <div className="card-body stack">
            <MachinePicker selected={targets} onAdd={(m) => setTargets((ts) => [...ts, m])} />
            {groups.status === "ok" && groups.data.items.length > 0 && (
              <fieldset className="day-picker">
                <legend>{t("actions.wizard.groups")}</legend>
                {groups.data.items.map((g) => (
                  <label key={g.id} className="check">
                    <input
                      type="checkbox"
                      className="checkbox"
                      checked={groupIds.includes(g.id)}
                      onChange={() =>
                        setGroupIds((ids) =>
                          ids.includes(g.id) ? ids.filter((x) => x !== g.id) : [...ids, g.id],
                        )
                      }
                    />
                    <span>
                      {g.name} <span className="muted small">({g.members})</span>
                    </span>
                  </label>
                ))}
              </fieldset>
            )}
            <label className="check">
              <input
                type="checkbox"
                className="checkbox"
                checked={allMachines}
                onChange={(e) => setAllMachines(e.target.checked)}
              />
              <span>
                {t("actions.wizard.allMachines")}
                <small className="muted block">{t("actions.wizard.allMachinesHint")}</small>
              </span>
            </label>
            {mismatch && (
              <div className="alert alert-danger">
                {t("actions.wizard.platformMismatch", { platform: t(`machines.platform.${pkg!.platform}`) })}
              </div>
            )}
            {targets.length === 0 ? (
              <p className="muted small">{t("actions.wizard.noTargets")}</p>
            ) : (
              <ul className="list-rows">
                {targets.map((m) => (
                  <li key={m.id}>
                    <PlatformIcon platform={m.os_platform} />
                    <span className="grow strong">{m.hostname}</span>
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      onClick={() => setTargets((ts) => ts.filter((x) => x.id !== m.id))}
                    >
                      {t("actions.wizard.remove")}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>

        <section className="card">
          <div className="card-header">
            <h2>{t("actions.wizard.options")}</h2>
          </div>
          <div className="card-body form-grid">
            <label>
              {t("actions.wizard.name")}
              <input
                className="input input-sm"
                maxLength={200}
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </label>
            <label>
              {t("actions.wizard.timeout")}
              <input
                className="input input-sm"
                type="number"
                min={30}
                max={86400}
                value={timeout}
                onChange={(e) => setTimeoutSec(Number(e.target.value))}
              />
            </label>
            <label>
              {t("actions.wizard.bandwidth")}
              <input
                className="input input-sm"
                type="number"
                min={0}
                max={limit || undefined}
                placeholder={String(limit || "")}
                value={bandwidth || ""}
                onChange={(e) => setBandwidth(Number(e.target.value))}
              />
              <span className="hint">{t("actions.wizard.bandwidthHint", { kbps: limit })}</span>
            </label>
            <label>
              {t("actions.wizard.expires")}
              <input
                className="input input-sm"
                type="number"
                min={1}
                max={720}
                placeholder={settings.status === "ok" ? String(settings.data.default_expiry_hours) : ""}
                value={expires || ""}
                onChange={(e) => setExpires(Number(e.target.value))}
              />
            </label>
            <label>
              {t("actions.wizard.retry")}
              <span className="report-actions">
                <input
                  className="input input-sm"
                  type="number"
                  min={0}
                  max={5}
                  aria-label={t("actions.wizard.retryCount")}
                  value={retryCount}
                  onChange={(e) => setRetryCount(Number(e.target.value))}
                />
                <input
                  className="input input-sm"
                  type="number"
                  min={1}
                  max={1440}
                  aria-label={t("actions.wizard.retryDelay")}
                  disabled={retryCount === 0}
                  value={retryDelay}
                  onChange={(e) => setRetryDelay(Number(e.target.value))}
                />
              </span>
              <span className="hint">{t("actions.wizard.retryHint")}</span>
            </label>
            <label>
              {t("actions.wizard.startAt")}
              <input
                className="input input-sm"
                type="datetime-local"
                value={startAt}
                onChange={(e) => setStartAt(e.target.value)}
              />
              <span className="hint">{t("actions.wizard.startAtHint")}</span>
            </label>
            <label>
              {t("actions.wizard.rollout")}
              <select
                className="select select-sm"
                value={rolloutPreset}
                onChange={(e) => setRolloutPreset(e.target.value as RolloutPreset)}
              >
                {(Object.keys(ROLLOUT_PRESETS) as RolloutPreset[]).map((p) => (
                  <option key={p} value={p}>
                    {t(`actions.rolloutPreset.${p}`)}
                  </option>
                ))}
              </select>
              <span className="hint">{t("actions.wizard.rolloutHint")}</span>
            </label>
          </div>
          <div className="card-body">
            <label className="check">
              <input
                type="checkbox"
                className="checkbox"
                checked={respectWindows}
                onChange={(e) => setRespectWindows(e.target.checked)}
              />
              <span>
                {t("actions.wizard.respectWindows")}
                <small className="muted block">{t("actions.wizard.respectWindowsHint")}</small>
              </span>
            </label>
          </div>
        </section>

        <div className="report-actions">
          <button
            type="submit"
            className="btn btn-primary"
            disabled={
              busy ||
              !allowed ||
              (targets.length === 0 && groupIds.length === 0 && !allMachines) ||
              Boolean(mismatch) ||
              (kind === "deploy_package" ? !packageId : !command.trim())
            }
          >
            {busy ? t("actions.wizard.submitting") : t("actions.wizard.submit")}
          </button>
        </div>
      </form>
    </div>
  );
}
