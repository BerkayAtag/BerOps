# Sunucu kurulumu

Automation BER sunucusu (`ber-server`) tek bir programdır. Hem konsolu (HTTPS, varsayılan 8443) hem ajan API'sini (karşılıklı TLS, varsayılan 52311) sunar ve veriyi PostgreSQL'de tutar.

Üç kurulum yolu vardır. Paketlerin tümü [GitHub Releases](https://github.com/BerkayAtag/automation-ber/releases/latest) sayfasındadır.

| Yol | Ne zaman? |
|---|---|
| [Windows Server MSI](#windows-server-msi) | Windows altyapısı, sihirbazla kurulum |
| [Docker Compose](#docker-compose-linux) | Linux, PostgreSQL ile birlikte tek komut |
| [Linux arşivi + systemd](#linux-arşivi-ve-systemd) | Konteynersiz Linux, mevcut PostgreSQL |

## Gereksinimler

- **PostgreSQL 15 veya üstü.** Boş bir veritabanı ve sahibi olan bir kullanıcı yeterlidir. Şema, ilk açılışta migration'larla oluşturulur.
- **Önerilen başlangıç:** 2 vCPU ve 4 GB RAM. Disk ihtiyacı paket kütüphanesine göre değişir; paket dosyaları veri klasöründe tutulur.
- **Ağ:** Konsol için TCP 8443 (yöneticilerden sunucuya), ajanlar için TCP 52311 (ajanlardan veya relay'lerden sunucuya).
- **CVE verisi için dış erişim:** `services.nvd.nist.gov`, `api.msrc.microsoft.com`, `www.cisa.gov`, `epss.empiricalsecurity.com`. İnternet yoksa [çevrim dışı klasör](cve.md) kullanılabilir.
- **Sunucu adı:** Ajanların sunucuya bağlanacağı DNS adı (ör. `ber.ornek.local`). Bu ad ajan sertifikasına yazılır; sonradan değişirse ajanlar yeni adla yeniden yapılandırılmalıdır.

## Windows Server MSI

`AutomationBER-Server-<sürüm>-x64.msi` dosyasını yönetici olarak çalıştırın. Sihirbazın adımları:

1. **Lisans** (Apache 2.0) ve **kurulum dizini.** Varsayılan: `C:\Program Files\Automation BER\Server`.
2. **Sunucu ayarları:**
   - PostgreSQL bağlantı adresi: `postgres://kullanıcı:parola@sunucu:5432/ber`.
   - Konsol ve ajan portları.
   - Sunucu DNS adları (virgülle ayrılır; ajanların bağlanacağı ad ilk sırada).
   - İsteğe bağlı konsol TLS sertifikası ve anahtarı (PEM). Boş bırakılırsa iç CA ile kendinden imzalı sertifika üretilir.
3. **İlk yönetici:** Kullanıcı adı ve en az 12 karakterlik parola. Bu hesap yerel **kurtarma hesabıdır**; Active Directory erişilemezse de giriş yapılabilir.
4. **Kurulum.** Sihirbaz şunları yapar:
   - `ber-server setup` ile yapılandırma dosyasını yazar, migration'ları uygular ve ilk yöneticiyi oluşturur.
   - `BERServer` servisini kurup başlatır.
   - Windows Güvenlik Duvarı'nda iki portu açar.

Veritabanına bağlanılamazsa kurulum hata verir ve geri alınır. Ayrıntılı günlük için `msiexec /i ... /l*v kurulum.log` kullanın. Parolalar günlüğe yazılmaz.

### Sessiz kurulum

```bat
msiexec /i AutomationBER-Server-1.0.0-x64.msi /qn ^
  DATABASE_URL="postgres://ber:PAROLA@db.ornek.local:5432/ber" ^
  HOSTNAMES=ber.ornek.local ADMIN_USERNAME=admin ADMIN_PASSWORD="EN-AZ-12-KARAKTER"
```

| Özellik | Varsayılan | Açıklama |
|---|---|---|
| `DATABASE_URL` | — | PostgreSQL bağlantı adresi (ilk kurulumda zorunlu) |
| `HOSTNAMES` | bilgisayar adı, `localhost` | Sertifikalardaki adlar, virgülle |
| `CONSOLE_PORT` | `8443` | Konsol portu |
| `AGENT_PORT` | `52311` | Ajan portu |
| `TLS_CERT`, `TLS_KEY` | — | Konsol sertifikası ve anahtarı (PEM dosya yolları) |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | `admin`, — | İlk yönetici (yalnızca hiç kullanıcı yoksa oluşturulur) |
| `INSTALLFOLDER` | `C:\Program Files\Automation BER\Server` | Program dizini |

### Dosya konumları

| Yol | İçerik |
|---|---|
| `C:\Program Files\Automation BER\Server\` | `ber-server.exe`, `console\` (konsol dosyaları) |
| `C:\ProgramData\BER\Server\ber-server.yaml` | Yapılandırma (veritabanı parolasını içerir; yalnızca yöneticiler okuyabilir) |
| `C:\ProgramData\BER\Server\data\pki\` | İç CA, aksiyon imza anahtarı, gizli değer anahtarı — **yedekleyin** |
| `C:\ProgramData\BER\Server\data\packages\` | Paket kütüphanesi dosyaları |
| `C:\ProgramData\BER\Server\data\logs\` | Servis günlükleri (döner, 20 MB × 5) |

**Yükseltme:** Yeni MSI'ı çalıştırmanız yeterlidir. Yapılandırma ve kullanıcılar korunur, migration'lar uygulanır.

**Kaldırma:** Programlar ve Özellikler'den kaldırılır. `C:\ProgramData\BER\Server` klasörü (iç CA dahil) bilerek korunur. Yeniden kurulumda ajanlar aynı CA ile çalışmaya devam eder. Tamamen silmek için klasörü elle kaldırın.

## Docker Compose (Linux)

```bash
git clone https://github.com/BerkayAtag/automation-ber.git && cd automation-ber
cp deploy/.env.example deploy/.env      # BER_DB_PASSWORD ve BER_HOSTNAMES değerlerini düzenleyin
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d
docker compose -f deploy/docker-compose.yml --env-file deploy/.env exec server ber-server admin create -username admin -recovery
```

- İmaj: `ghcr.io/berkayatag/automation-ber-server:<sürüm>`. `BER_IMAGE` ile sürüm sabitleyin.
- Veri `berdata` biriminde (`/var/lib/ber`), veritabanı `pgdata` biriminde tutulur.
- CA parmak izi: `docker compose ... logs server | grep parmak_izi`.

## Linux arşivi ve systemd

```bash
tar -xzf automation-ber-server-1.0.0-linux-amd64.tar.gz -C /opt
sudo useradd --system --home /var/lib/ber --create-home ber
sudo -u ber /opt/automation-ber-server-1.0.0-linux-amd64/ber-server setup \
  -config /etc/ber/ber-server.yaml -data-dir /var/lib/ber \
  -database-url 'postgres://ber:PAROLA@localhost:5432/ber' \
  -hostnames ber.ornek.local -static-dir /opt/automation-ber-server-1.0.0-linux-amd64/console \
  -admin-username admin            # parola BER_ADMIN_PASSWORD ortam değişkeninden okunur
```

`/etc/systemd/system/ber-server.service`:

```ini
[Unit]
Description=Automation BER Server
After=network-online.target postgresql.service

[Service]
User=ber
ExecStart=/opt/automation-ber-server-1.0.0-linux-amd64/ber-server serve -config /etc/ber/ber-server.yaml
Restart=on-failure
AmbientCapabilities=
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/ber

[Install]
WantedBy=multi-user.target
```

## Kurulumdan sonra

1. **Konsola girin:** `https://<sunucu>:8443`. Sertifika iç CA'dan üretildiyse tarayıcı uyarı verir. `data/pki/ca.crt` dosyasını yönetici bilgisayarlarına güvenilir kök olarak dağıtın veya kurumsal bir sertifika kullanın.
2. **Kayıt anahtarı üretin:** *Ajan indir* sayfası, sunucu adresi, kayıt anahtarı ve CA parmak izi gömülü kurulum komutlarını hazırlar. Ayrıntılar: [Windows ajanı](kurulum-ajan-windows.md), [macOS ajanı](kurulum-ajan-macos.md).
3. **Active Directory (isteğe bağlı):** Ayarlar → Active Directory ([ad-entegrasyonu.md](ad-entegrasyonu.md)).
4. **CVE kaynakları:** İlk eşitleme açılıştan sonra kendiliğinden başlar. NVD için API anahtarı (`BER_NVD_API_KEY`) eşitlemeyi hızlandırır ([cve.md](cve.md)).
5. **Şubeler:** Gerekirse relay kurun ([relay/README.md](../relay/README.md)).

## Yapılandırma başvurusu

`ber-server.yaml` (tüm alanlar isteğe bağlıdır, varsayılanlar gösterilmiştir):

```yaml
data_dir: data
database_url: postgres://...          # veya BER_DATABASE_URL
log_level: info                       # debug, info, warn, error
console:
  listen: ":8443"
  hostnames: [localhost, 127.0.0.1]   # veya BER_HOSTNAMES (konsol + ajan)
  tls_cert_file: ""                   # boşsa iç CA'dan üretilir
  tls_key_file: ""
  static_dir: ""                      # konsol dosyaları; veya BER_CONSOLE_STATIC_DIR
agent:
  listen: ":52311"
  hostnames: [localhost, 127.0.0.1]
  heartbeat_seconds: 60
  cert_validity: 8760h
session:
  idle_timeout: 30m
  absolute_timeout: 12h
cve:
  enabled: true
  sync_interval: 24h
  nvd_api_key: ""                     # tercihen BER_NVD_API_KEY
  msrc_months: 12
  offline_dir: ""
```

## Yedekleme

- **PostgreSQL:** `pg_dump` ile düzenli yedek alın.
- **Veri klasörü:** Özellikle `data/pki/` yedeklenmelidir. İç CA kaybolursa tüm ajanların yeniden kurulması gerekir. Gizli değer anahtarı kaybolursa AD ve bildirim parolaları yeniden girilmelidir. `data/packages/` paket kütüphanesini içerir.
