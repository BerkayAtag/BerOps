import { createColumnHelper, type PaginationState, type SortingState } from "@tanstack/react-table";
import { useMemo, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";
import { apiUpload, errorKey, type Installer, type Package } from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";
import { PlatformIcon } from "../components/Badges";
import { DataTable } from "../components/DataTable";
import { formatBytes, formatDate, formatPercent } from "../format";

const col = createColumnHelper<Package>();

const INSTALLERS: Record<"windows" | "darwin", Installer[]> = {
  windows: ["msi", "exe", "file"],
  darwin: ["pkg", "dmg", "file"],
};
const SHELLS = { windows: ["cmd", "powershell"], darwin: ["sh", "zsh"] } as const;

function UploadForm({ onDone }: { onDone: () => void }) {
  const { t, i18n } = useTranslation();
  const [platform, setPlatform] = useState<"windows" | "darwin">("windows");
  const [installer, setInstaller] = useState<Installer>("msi");
  const [file, setFile] = useState<File | null>(null);
  const [fields, setFields] = useState({
    name: "",
    version: "",
    publisher: "",
    install_command: "",
    shell: "",
    success_codes: "",
    detect_name: "",
    description: "",
  });
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const set = (k: keyof typeof fields) => (e: { target: { value: string } }) =>
    setFields({ ...fields, [k]: e.target.value });

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!file) return;
    setError(null);
    const codes = fields.success_codes
      .split(",")
      .map((c) => c.trim())
      .filter(Boolean)
      .map(Number);
    const meta = {
      ...fields,
      platform,
      installer,
      success_codes: codes.length ? codes : undefined,
    };
    const form = new FormData();
    form.append("metadata", JSON.stringify(meta));
    form.append("file", file);
    setProgress(0);
    try {
      await apiUpload("/api/v1/packages", form, setProgress);
      setProgress(null);
      onDone();
    } catch (err) {
      setProgress(null);
      const msg =
        err instanceof Error && "code" in err && err.code === "request.invalid" ? err.message : null;
      setError(msg ?? t(errorKey(err), { defaultValue: t("errors.unknown") }));
    }
  }

  return (
    <form className="card-body stack" onSubmit={(e) => void submit(e)}>
      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}
      <div className="form-grid">
        <label>
          {t("packages.field.platform")}
          <select
            className="select select-sm"
            value={platform}
            onChange={(e) => {
              const p = e.target.value as "windows" | "darwin";
              setPlatform(p);
              setInstaller(INSTALLERS[p][0]!);
              setFields({ ...fields, shell: "" });
            }}
          >
            <option value="windows">{t("machines.platform.windows")}</option>
            <option value="darwin">{t("machines.platform.darwin")}</option>
          </select>
        </label>
        <label>
          {t("packages.field.installer")}
          <select
            className="select select-sm"
            value={installer}
            onChange={(e) => setInstaller(e.target.value as Installer)}
          >
            {INSTALLERS[platform].map((i) => (
              <option key={i} value={i}>
                {t(`packages.installer.${i}`)}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("packages.field.name")}
          <input className="input input-sm" required value={fields.name} onChange={set("name")} />
        </label>
        <label>
          {t("packages.field.version")}
          <input className="input input-sm" required value={fields.version} onChange={set("version")} />
        </label>
        <label>
          {t("packages.field.publisher")}
          <input className="input input-sm" value={fields.publisher} onChange={set("publisher")} />
        </label>
        <label>
          {t("packages.field.file")}
          <input
            className="input input-sm"
            type="file"
            required
            accept={installer === "file" ? undefined : `.${installer}`}
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
        </label>
      </div>
      <div className="form-grid">
        <label className="span-2">
          {t("packages.field.command")}
          <input
            className="input input-sm mono"
            value={fields.install_command}
            required={installer === "exe" || installer === "file"}
            placeholder={
              installer === "msi"
                ? 'msiexec.exe /i "{file}" /qn /norestart'
                : installer === "pkg"
                  ? '/usr/sbin/installer -pkg "{file}" -target /'
                  : installer === "exe"
                    ? '"{file}" /S'
                    : ""
            }
            onChange={set("install_command")}
          />
          <span className="hint">
            {installer === "dmg" ? t("packages.hint.dmg") : t("packages.hint.command")}
          </span>
        </label>
        <label>
          {t("packages.field.shell")}
          <select className="select select-sm" value={fields.shell} onChange={set("shell")}>
            <option value="">—</option>
            {SHELLS[platform].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("packages.field.successCodes")}
          <input
            className="input input-sm mono"
            value={fields.success_codes}
            placeholder="0, 3010"
            onChange={set("success_codes")}
          />
          <span className="hint">{t("packages.hint.successCodes")}</span>
        </label>
        <label className="span-2">
          {t("packages.field.detectName")}
          <input className="input input-sm mono" value={fields.detect_name} onChange={set("detect_name")} />
          <span className="hint">{t("packages.hint.detectName")}</span>
        </label>
      </div>
      <div className="report-actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={progress !== null || !file}>
          {progress !== null
            ? t("packages.uploading", { pct: formatPercent(progress * 100, i18n.language) })
            : t("packages.upload")}
        </button>
        {progress !== null && (
          <div className="gauge-bar upload-bar">
            <div className="gauge-fill" style={{ width: `${progress * 100}%` }} />
          </div>
        )}
      </div>
    </form>
  );
}

export function PackagesPage() {
  const { t, i18n } = useTranslation();
  const { can } = useAuth();
  const navigate = useNavigate();
  const [platform, setPlatform] = useState("");
  const [search, setSearch] = useState("");
  const [showUpload, setShowUpload] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const q = new URLSearchParams({ platform, q: search });
  const [list, reload] = useApi<{ items: Package[] }>(`/api/v1/packages?${q}`);
  const [sorting, setSorting] = useState<SortingState>([{ id: "name", desc: false }]);
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });

  const columns = useMemo(
    () => [
      col.accessor("name", {
        header: t("packages.col.name"),
        cell: (c) => (
          <span className="cell-host">
            <PlatformIcon platform={c.row.original.platform} />
            <span>
              <Link
                to={`/paketler/${c.row.original.id}`}
                className="strong"
                onClick={(e) => e.stopPropagation()}
              >
                {c.getValue()}
              </Link>
              {c.row.original.publisher && <span className="muted small"> · {c.row.original.publisher}</span>}
            </span>
          </span>
        ),
      }),
      col.accessor("version", {
        header: t("packages.col.version"),
        cell: (c) => <span className="mono">{c.getValue()}</span>,
      }),
      col.accessor("installer", {
        header: t("packages.col.installer"),
        cell: (c) => <span className="tag">{t(`packages.installer.${c.getValue()}`)}</span>,
      }),
      col.accessor("file_size", {
        header: t("packages.col.size"),
        cell: (c) => formatBytes(c.getValue(), i18n.language),
      }),
      col.accessor("created_at", {
        header: t("packages.col.created"),
        cell: (c) => formatDate(c.getValue(), i18n.language),
      }),
    ],
    [t, i18n.language],
  );

  return (
    <div className="page">
      <header className="page-header page-header-row">
        <div>
          <h1>{t("packages.title")}</h1>
          <p className="muted">{t("packages.subtitle")}</p>
        </div>
        {can("packages.upload") && (
          <button type="button" className="btn btn-primary" onClick={() => setShowUpload((v) => !v)}>
            {t("packages.upload")}
          </button>
        )}
      </header>
      {notice && (
        <div className="alert alert-info" role="status">
          {notice}
        </div>
      )}
      {showUpload && (
        <section className="card">
          <div className="card-header">
            <h2>{t("packages.uploadTitle")}</h2>
          </div>
          <UploadForm
            onDone={() => {
              setShowUpload(false);
              setNotice(t("packages.uploaded"));
              reload();
            }}
          />
        </section>
      )}
      <section className="card">
        <div className="toolbar">
          <label className="search">
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <circle cx="11" cy="11" r="7" />
              <path d="m20 20-3.5-3.5" />
            </svg>
            <input
              className="input"
              type="search"
              aria-label={t("common.search")}
              placeholder={t("packages.searchPlaceholder")}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </label>
          <select
            className="select"
            aria-label={t("packages.col.platform")}
            value={platform}
            onChange={(e) => setPlatform(e.target.value)}
          >
            <option value="">
              {t("packages.col.platform")}: {t("common.all")}
            </option>
            <option value="windows">{t("machines.platform.windows")}</option>
            <option value="darwin">{t("machines.platform.darwin")}</option>
          </select>
        </div>
        <DataTable
          label={t("packages.title")}
          data={list.status === "ok" ? list.data.items : []}
          columns={columns}
          getRowId={(p) => p.id}
          loading={list.status === "loading"}
          emptyText={t("packages.empty")}
          sorting={sorting}
          onSortingChange={setSorting}
          pagination={pagination}
          onPaginationChange={setPagination}
          onRowClick={(p) => navigate(`/paketler/${p.id}`)}
        />
      </section>
    </div>
  );
}
