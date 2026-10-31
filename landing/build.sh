#!/bin/sh
# Tanıtım sayfasını GitHub Pages için tek klasörde toplar: landing/ + ortak tasarım token'ları.
# Kullanım: landing/build.sh <çıktı klasörü>
set -eu
OUT=${1:?çıktı klasörü gerekli}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT/img"
cp "$HERE/index.html" "$HERE/landing.css" "$HERE/landing.js" "$HERE/init.js" "$OUT/"
cp "$HERE"/img/*.webp "$OUT/img/"
cp "$HERE/../design/tokens.css" "$OUT/tokens.css"
cp "$HERE/../console/public/favicon.svg" "$OUT/"
touch "$OUT/.nojekyll"
echo "Tanıtım sayfası hazır: $OUT"
