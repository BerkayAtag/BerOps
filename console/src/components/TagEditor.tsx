import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { api, errorKey } from "../api/client";
import { useApi } from "../api/useApi";

// TagEditor, makinenin etiketlerini gösterir ve (izin varsa) düzenler.
export function TagEditor({ machineId, editable }: { machineId: string; editable: boolean }) {
  const { t } = useTranslation();
  const [resp, reload] = useApi<{ tags: string[] }>(`/api/v1/machines/${machineId}/tags`);
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const tags = resp.status === "ok" ? resp.data.tags : [];

  async function save(next: string[]): Promise<boolean> {
    setError(null);
    try {
      await api(`/api/v1/machines/${machineId}/tags`, { method: "PUT", body: { tags: next } });
      reload();
      return true;
    } catch (err) {
      const invalid = err instanceof Error && "code" in err && err.code === "request.invalid";
      setError(invalid ? err.message : t(errorKey(err), { defaultValue: t("errors.unknown") }));
      return false;
    }
  }

  function add(e: FormEvent) {
    e.preventDefault();
    const v = input.trim();
    if (!v || tags.includes(v)) return;
    setInput("");
    // Hata olursa yazılan etiket düzeltilebilsin diye kutuya geri konur.
    void save([...tags, v]).then((ok) => !ok && setInput(v));
  }

  if (!editable && tags.length === 0) return null;
  return (
    <div className="stack">
      <div className="pills">
        <span className="muted small">{t("groups.tags")}:</span>
        {tags.length === 0 && <span className="muted small">—</span>}
        {tags.map((tag) => (
          <span key={tag} className="tag">
            <Link to={`/makineler?tag=${encodeURIComponent(tag)}`}>{tag}</Link>
            {editable && (
              <button
                type="button"
                className="tag-remove"
                aria-label={t("groups.removeTag", { tag })}
                onClick={() => void save(tags.filter((x) => x !== tag))}
              >
                ×
              </button>
            )}
          </span>
        ))}
        {editable && (
          <form className="inline-form" onSubmit={add}>
            <input
              className="input input-sm"
              maxLength={40}
              aria-label={t("groups.newTag")}
              placeholder={t("groups.newTag")}
              value={input}
              onChange={(e) => setInput(e.target.value)}
            />
          </form>
        )}
      </div>
      {error && <span className="text-danger small">{error}</span>}
    </div>
  );
}
