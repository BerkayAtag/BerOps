#!/bin/sh
# BerOps Agent'ı macOS'tan iz bırakmadan kaldırır.
# Kullanım: sudo berops-agent-uninstall [-code KALDIRMA_KODU]
# Kaldırma koruması konsolda açıksa kod gerekir (BEROPS_UNINSTALL_CODE ortam değişkeniyle de verilebilir).
set -eu
CODE="${BEROPS_UNINSTALL_CODE:-}"
while [ $# -gt 0 ]; do
	case "$1" in
	-code | --code)
		[ $# -ge 2 ] || { echo "-code bir değer ister" >&2; exit 2; }
		CODE="$2"
		shift 2
		;;
	*)
		echo "Bilinmeyen seçenek: $1" >&2
		exit 2
		;;
	esac
done
if [ "$(id -u)" -ne 0 ]; then
	echo "Bu betik root olarak çalıştırılmalı: sudo $0" >&2
	exit 1
fi
BIN=/usr/local/bin/berops-agent
DATA="/Library/Application Support/BerOps/Agent"
if [ -x "$BIN" ]; then
	# Kod süreç listesinde görünmesin diye ortam değişkeniyle verilir.
	if ! BEROPS_UNINSTALL_CODE="$CODE" "$BIN" uninstall-check >/dev/null; then
		echo "Kaldırma reddedildi: kaldırma kodu hatalı veya verilmedi (sudo $0 -code ...)." >&2
		exit 1
	fi
elif [ -e "$DATA/protection.json" ]; then
	# Ajan ikilisi yok veya çalıştırılamıyor ama koruma açık: kod doğrulanamadığı için reddedilir.
	echo "Kaldırma reddedildi: kaldırma koruması açık ve kod doğrulanamıyor ($BIN bulunamadı)." >&2
	exit 1
fi
LABEL=io.github.berkayatag.berops.agent
launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootout "system/$LABEL.update" 2>/dev/null || true
rm -f "/Library/LaunchDaemons/$LABEL.plist" "$BIN" /usr/local/bin/berops-agent-uninstall
rm -rf "$DATA"
rmdir "/Library/Application Support/BerOps" 2>/dev/null || true
pkgutil --forget io.github.berkayatag.berops.agent.pkg >/dev/null 2>&1 || true
echo "BerOps Agent kaldırıldı. Makine konsolda çevrimdışı görünecektir; gerekirse oradan silin."
