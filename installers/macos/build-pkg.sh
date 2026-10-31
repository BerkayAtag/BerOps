#!/bin/sh
# BerOps Agent macOS paketini (.pkg) üretir.
#
# Kullanım: installers/macos/build-pkg.sh <sürüm> <universal berops-agent> <çıktı.pkg>
#
# İsteğe bağlı ortam değişkenleri (CI'da GitHub Secrets'tan gelir):
#   MACOS_INSTALLER_IDENTITY  "Developer ID Installer: ..." — verilirse paket imzalanır
#   MACOS_APP_IDENTITY        "Developer ID Application: ..." — verilirse ikili dosya imzalanır
#   NOTARY_PROFILE            notarytool anahtar zinciri profili — verilirse paket notarize edilir
set -eu
VERSION=$1
BINARY=$2
OUT=$3
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

ROOT="$WORK/root"
mkdir -p "$ROOT/usr/local/bin" "$ROOT/Library/LaunchDaemons"
cp "$BINARY" "$ROOT/usr/local/bin/berops-agent"
cp "$HERE/uninstall.sh" "$ROOT/usr/local/bin/berops-agent-uninstall"
cp "$HERE/io.github.berkayatag.berops.agent.plist" "$ROOT/Library/LaunchDaemons/"
chmod 755 "$ROOT/usr/local/bin/berops-agent" "$ROOT/usr/local/bin/berops-agent-uninstall"
chmod 644 "$ROOT/Library/LaunchDaemons/io.github.berkayatag.berops.agent.plist"

if [ -n "${MACOS_APP_IDENTITY:-}" ]; then
	codesign --force --options runtime --timestamp --identifier berops-agent \
		--sign "$MACOS_APP_IDENTITY" "$ROOT/usr/local/bin/berops-agent"
fi

pkgbuild --root "$ROOT" --scripts "$HERE/scripts" \
	--identifier io.github.berkayatag.berops.agent.pkg --version "$VERSION" \
	--install-location / --ownership recommended \
	"$WORK/berops-agent-component.pkg"

mkdir -p "$WORK/resources"
cp "$HERE"/resources/*.html "$WORK/resources/"
cp "$HERE/../../LICENSE" "$WORK/resources/license.txt"
sed "s/__VERSION__/$VERSION/" "$HERE/distribution.xml" >"$WORK/distribution.xml"

if [ -n "${MACOS_INSTALLER_IDENTITY:-}" ]; then
	productbuild --distribution "$WORK/distribution.xml" --resources "$WORK/resources" \
		--package-path "$WORK" --sign "$MACOS_INSTALLER_IDENTITY" "$OUT"
else
	productbuild --distribution "$WORK/distribution.xml" --resources "$WORK/resources" \
		--package-path "$WORK" "$OUT"
fi

if [ -n "${NOTARY_PROFILE:-}" ] && [ -n "${MACOS_INSTALLER_IDENTITY:-}" ]; then
	xcrun notarytool submit "$OUT" --keychain-profile "$NOTARY_PROFILE" --wait
	xcrun stapler staple "$OUT"
fi
echo "Paket hazır: $OUT"
