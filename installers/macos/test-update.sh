#!/bin/bash
# CI: Kurulu macOS ajanının sunucuya kaydolup sunucudan gönderilen aksiyonla yeni paket
# sürümüne kendini güncellediğini uçtan uca doğrular. Ajan paketi önceden kurulmuş olmalı.
# Kullanım: test-update.sh <berops-server> <yeni.pkg> <beklenen sürüm> <veritabanı adresi>
set -euo pipefail
SERVER_BIN=$1 NEW_PKG=$2 WANT=$3 DB=$4
W=$(mktemp -d)
export BER_ADMIN_PASSWORD="Ci-$(uuidgen)"
"$SERVER_BIN" setup -config "$W/server.yaml" -data-dir "$W/data" -database-url "$DB" \
	-hostnames localhost -admin-username ci-admin
echo "  heartbeat_seconds: 10" >>"$W/server.yaml"
"$SERVER_BIN" serve -config "$W/server.yaml" >"$W/server.log" 2>&1 &
SPID=$!
trap 'kill $SPID 2>/dev/null || true; tail -n 40 "$W/server.log"' EXIT

B=https://localhost:8443
for _ in $(seq 60); do curl -skf "$B/api/v1/health" >/dev/null && break || sleep 1; done
CSRF=$(curl -skf -c "$W/cj" -H 'Content-Type: application/json' \
	-d "{\"username\":\"ci-admin\",\"password\":\"$BER_ADMIN_PASSWORD\"}" "$B/api/v1/auth/login" | jq -r .csrf_token)
api() { # api METHOD YOL [JSON]
	curl -skf -b "$W/cj" -X "$1" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' ${3:+-d "$3"} "$B$2"
}
wait_for() { # wait_for SANİYE AÇIKLAMA KOMUT...
	local n=$1 what=$2
	shift 2
	for _ in $(seq "$n"); do "$@" && return 0 || sleep 3; done
	echo "ZAMAN AŞIMI: $what" >&2
	return 1
}

INFO=$(api GET /api/v1/server-info)
KEY=$(api POST /api/v1/registration-keys '{"name":"ci","require_approval":false}' | jq -r .secret)
sudo /usr/local/bin/berops-agent configure -server "$(jq -r .agent_url <<<"$INFO")" -key "$KEY" \
	-ca-hash "$(jq -r .ca_fingerprint <<<"$INFO")" >/dev/null
machine() { api GET /api/v1/machines | jq -r '.items[] | select(.status == "active" and .agent_version != "") | .id' | head -n 1; }
enrolled() { test -n "$(machine)"; }
wait_for 40 "ajan kaydolmadı" enrolled
MID=$(machine)
echo "✓ Ajan kaydoldu: $MID"

PKG=$(curl -skf -b "$W/cj" -H "X-CSRF-Token: $CSRF" \
	-F 'metadata={"name":"BerOps Agent","version":"ci-guncelleme","platform":"darwin","installer":"pkg"}' \
	-F "file=@$NEW_PKG" "$B/api/v1/packages" | jq -r .id)
AID=$(api POST /api/v1/actions "{\"kind\":\"update_agent\",\"package_id\":\"$PKG\",\"machine_ids\":[\"$MID\"]}" | jq -r .id)
target() { api GET "/api/v1/actions/$AID" | jq -r '.targets[0].status'; }
finished() { [[ $(target) =~ ^(succeeded|failed)$ ]]; }
wait_for 100 "ajan güncellemesi sonuçlanmadı" finished
api GET "/api/v1/actions/$AID" | jq '.targets[0] | {status, error, stdout, exit_code}'
test "$(target)" = succeeded
/usr/local/bin/berops-agent version | grep -F "$WANT"
sudo launchctl print system/io.github.berkayatag.berops.agent | grep -q "state = running"
# Yeni ajan, installer bitince (paket kaydı yazıldıktan sonra) tek seferlik işi kaldırır.
update_job_gone() { ! sudo launchctl print system/io.github.berkayatag.berops.agent.update >/dev/null 2>&1; }
wait_for 20 "tek seferlik güncelleme işi kaldırılmadı" update_job_gone
pkgutil --pkg-info io.github.berkayatag.berops.agent.pkg | grep -F "version: $WANT"
echo "✓ Ajan $WANT sürümüne güncellendi; tek seferlik güncelleme işi kaldırıldı"
