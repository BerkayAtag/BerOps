#!/usr/bin/env bash
# PreToolUse: public repoya marka adı veya gizli anahtar yazılmasını engeller.
# .claude/ altındaki yapılandırma dosyaları denetim dışıdır (bu script kalıpları içerir).

input=$(cat)
f=$(echo "$input" | jq -r '.tool_input.file_path // empty')

case "$f" in
  */.claude/*) exit 0 ;;
esac

content=$(echo "$input" | jq -r '[.tool_input.content, .tool_input.new_string] | map(select(. != null)) | join("\n")')

# Yasaklı marka adı, repoda düz metin olarak geçmemesi için base64 ile saklanır.
brand=$(printf '%s' 'YWtiYW5r' | base64 -d)
if echo "$content" | grep -qi -- "$brand"; then
  echo "Engellendi ($f): marka adı repoya yazılamaz. Renkler için --ber-* token'larını kullanın." >&2
  exit 2
fi

if echo "$content" | grep -qE -- '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----'; then
  echo "Engellendi ($f): özel anahtar repoya yazılamaz. Testlerde anahtarları çalışma anında üretin." >&2
  exit 2
fi

if echo "$content" | grep -qE '(ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})'; then
  echo "Engellendi ($f): gerçek bir token'a benzeyen değer bulundu. GitHub Secrets veya ortam değişkeni kullanın." >&2
  exit 2
fi

exit 0
