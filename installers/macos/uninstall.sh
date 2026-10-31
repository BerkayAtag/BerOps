#!/bin/sh
# Automation BER Agent'ı macOS'tan iz bırakmadan kaldırır. Kullanım: sudo ./uninstall.sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
	echo "Bu betik root olarak çalıştırılmalı: sudo $0" >&2
	exit 1
fi
LABEL=io.github.berkayatag.ber.agent
launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "/Library/LaunchDaemons/$LABEL.plist" /usr/local/bin/ber-agent /usr/local/bin/ber-agent-uninstall
rm -rf "/Library/Application Support/BER/Agent"
rmdir "/Library/Application Support/BER" 2>/dev/null || true
pkgutil --forget io.github.berkayatag.ber.agent.pkg >/dev/null 2>&1 || true
echo "Automation BER Agent kaldırıldı. Makine konsolda çevrimdışı görünecektir; gerekirse oradan silin."
