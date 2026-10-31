import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useParams } from "react-router";
import { api, errorKey, type PackageDetail } from "../api/client";
import { useApi } from "../api/useApi";
import { useAuth } from "../auth/AuthProvider";
import { PlatformIcon } from "../components/Badges";
import { formatBytes, formatDateTime } from "../format";

export function PackageDetailPage() {
  const { id = "" } = useParams();
  const { t, i18n } = useTranslation();
  const { can } = useAuth();
  const navigate = useNavigate();
  const [detail] = useApi<PackageDetail>(`/api/v1/packages/${id}`);
  const [error, setError] = useState<string | null>(null);

  if (detail.status === "loading") return <p className="muted">{t("common.loading")}</p>;
  if (detail.status === "error") {
    return (
      <div className="page">
        <Link to="/paketler" className="back-link">
          ← {t("packages.title")}
        </Link>
        <div className="alert alert-danger" role="alert">
          {t(detail.error, { defaultValue: t("errors.unknown") })}
        </div>
      </div>
    );
  }
  const p = detail.data;
  const canDeploy = can("actions.deploy_package");
  const deployUrl = (ids: string[]) =>
    `/aksiyonlar/yeni?kind=deploy_package&package=${p.id}${ids.length ? `&machines=${ids.join(",")}` : ""}`;

  async function remove() {
    if (!window.confirm(t("packages.deleteConfirm", { name: `${p.name} ${p.version}` }))) return;
    try {
      await api(`/api/v1/packages/${p.id}`, { method: "DELETE" });
      navigate("/paketler");
    } catch (err) {
      setError(t(errorKey(err), { defaultValue: t("errors.unknown") }));
    }
  }

  return (
    <div className="page">
      <Link to="/paketler" className="back-link">
        ← {t("packages.title")}
      </Link>
      <header className="page-header page-header-row">
        <div className="title-with-icon">
          <PlatformIcon platform={p.platform} />
          <div>
            <h1>
              {p.name} <span className="mono muted">{p.version}</span>
            </h1>
            <p className="muted">{p.publisher}</p>
          </div>
        </div>
        <div className="report-actions">
          {canDeploy && (
            <Link className="btn btn-primary" to={deployUrl([])}>
              {t("packages.deploy")}
            </Link>
          )}
          {can("packages.delete") && (
            <button type="button" className="btn btn-ghost" onClick={() => void remove()}>
              {t("packages.delete")}
            </button>
          )}
        </div>
      </header>
      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}
      <div className="detail-grid">
        <section className="card">
          <div className="card-header">
            <h2>{t("packages.detail")}</h2>
          </div>
          <dl className="card-body fields">
            <div className="field-row">
              <dt>{t("packages.field.installer")}</dt>
              <dd>{t(`packages.installer.${p.installer}`)}</dd>
            </div>
            <div className="field-row">
              <dt>{t("packages.field.file")}</dt>
              <dd>
                <span className="mono">{p.file_name}</span> ({formatBytes(p.file_size, i18n.language)})
              </dd>
            </div>
            <div className="field-row">
              <dt>{t("packages.sha")}</dt>
              <dd className="mono small cell-wrap">{p.file_sha256}</dd>
            </div>
            <div className="field-row">
              <dt>{t("packages.field.command")}</dt>
              <dd className="mono small cell-wrap">
                {p.install_command || "—"} <span className="tag">{p.shell}</span>
              </dd>
            </div>
            <div className="field-row">
              <dt>{t("packages.field.successCodes")}</dt>
              <dd className="mono">{p.success_codes.join(", ")}</dd>
            </div>
            <div className="field-row">
              <dt>{t("packages.field.detectName")}</dt>
              <dd className="mono">{p.detect_name || "—"}</dd>
            </div>
            <div className="field-row">
              <dt>{t("packages.col.created")}</dt>
              <dd>{formatDateTime(p.created_at, i18n.language)}</dd>
            </div>
          </dl>
        </section>
        <section className="card">
          <div className="card-header card-header-row">
            <h2>{t("packages.outdated", { count: p.outdated.length })}</h2>
            {canDeploy && p.outdated.length > 0 && (
              <Link className="btn btn-primary btn-sm" to={deployUrl(p.outdated.map((o) => o.machine_id))}>
                {t("packages.deployOutdated")}
              </Link>
            )}
          </div>
          {!p.detect_name ? (
            <p className="card-body muted small">{t("packages.noDetect")}</p>
          ) : (
            <>
              <p className="card-body muted small">{t("packages.upToDate", { count: p.up_to_date })}</p>
              <ul className="list-rows">
                {p.outdated.map((o) => (
                  <li key={o.machine_id}>
                    <Link to={`/makineler/${o.machine_id}`} className="grow strong">
                      {o.hostname}
                    </Link>
                    <span className="muted small">{o.name}</span>
                    <span className="tag mono" title={t("packages.installedVersion")}>
                      {o.version}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
      </div>
    </div>
  );
}
