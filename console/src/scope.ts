/** Satır satır girilen OU DN'lerini diziye çevirir. */
export function parseScope(text: string) {
  return text
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}
