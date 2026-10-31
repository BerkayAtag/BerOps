#!/usr/bin/env bash
# PostToolUse: düzenlenen dosyayı türüne göre biçimlendirir.
# Biçimlendirici kurulu değilse sessizce geçer; düzenlemeyi asla engellemez.

f=$(jq -r '.tool_input.file_path // empty')
[ -z "$f" ] || [ ! -f "$f" ] && exit 0

case "$f" in
  *.go)
    command -v gofmt >/dev/null && gofmt -w "$f"
    ;;
  *.ts|*.tsx|*.js|*.jsx|*.css|*.scss|*.json|*.html)
    command -v npx >/dev/null && npx --no-install prettier --write "$f" >/dev/null 2>&1
    ;;
esac

exit 0
