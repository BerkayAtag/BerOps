#!/bin/sh
# BerOps Agent'ı macOS'tan iz bırakmadan kaldırır. Kullanım: sudo ./uninstall.sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
	echo "Bu betik root olarak çalıştırılmalı: sudo $0" >&2
	exit 1
fi
LABEL=io.github.berkayatag.berops.agent
launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "/Library/LaunchDaemons/$LABEL.plist" /usr/local/bin/berops-agent /usr/local/bin/berops-agent-uninstall
rm -rf "/Library/Application Support/BerOps/Agent"
rmdir "/Library/Application Support/BerOps" 2>/dev/null || true
pkgutil --forget io.github.berkayatag.berops.agent.pkg >/dev/null 2>&1 || true
echo "BerOps Agent kaldırıldı. Makine konsolda çevrimdışı görünecektir; gerekirse oradan silin."
