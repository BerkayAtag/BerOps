import { describe, expect, it } from "vitest";
import en from "./locales/en.json";
import tr from "./locales/tr.json";

function keys(obj: object, prefix = ""): string[] {
  return Object.entries(obj).flatMap(([k, v]) =>
    v !== null && typeof v === "object" ? keys(v as object, `${prefix}${k}.`) : [`${prefix}${k}`],
  );
}

function values(obj: object): string[] {
  return Object.values(obj).flatMap((v) => (typeof v === "object" ? values(v as object) : [String(v)]));
}

describe("çeviriler", () => {
  it("Türkçe ve İngilizce aynı anahtarlara sahip", () => {
    expect(keys(en).sort()).toEqual(keys(tr).sort());
  });

  it("boş çeviri yok", () => {
    for (const v of [...values(tr), ...values(en)]) expect(v.trim()).not.toBe("");
  });

  it("API hata kodlarının tümü çevrilmiş", () => {
    const codes = [
      "auth.invalid_credentials",
      "auth.rate_limited",
      "auth.unauthenticated",
      "auth.forbidden",
      "auth.csrf",
      "request.invalid",
    ];
    const trKeys = new Set(keys(tr));
    for (const c of codes) expect(trKeys.has(`errors.${c}`)).toBe(true);
  });
});
