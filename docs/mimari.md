# Automation BER — Mimari

Bu belge Automation BER'in bileşenlerini, aralarındaki iletişimi, güvenlik modelini ve veritabanı şemasını özetler. Ayrıntılı kararlar ve varsayımlar için [varsayimlar.md](varsayimlar.md) dosyasına bakın.

## 1. Bileşenler

```
                        ┌──────────────────────────────┐
   Tarayıcı (Konsol) ──▶│  BER Server                  │
   HTTPS :8443          │  ├─ Konsol API + statik UI   │
                        │  ├─ Ajan API (mTLS) :52311   │
                        │  ├─ İç CA (PKI)              │
                        │  ├─ Zamanlayıcı / iş kuyruğu │
                        │  ├─ CVE senkronizasyonu      │
                        │  └─ Paket deposu             │
                        └──────┬───────────────┬───────┘
                               │ PostgreSQL    │ mTLS
                               ▼               ▼
                        ┌────────────┐   ┌───────────────┐
                        │ PostgreSQL │   │ BER Relay     │ (opsiyonel, şube)
                        └────────────┘   │ önbellekli    │
                                         │ dağıtım       │
                                         └──────┬────────┘
                                                │ mTLS
                               ┌────────────────┼────────────────┐
                               ▼                ▼                ▼
                         BER Agent         BER Agent        BER Agent
                         (Windows)         (macOS)          (Windows)
```

| Bileşen | Dil / Teknoloji | Görev |
|---|---|---|
| **BER Server** (`server/`) | Go, `net/http`, PostgreSQL (pgx) | Merkezi API, kimlik doğrulama, RBAC, iç CA, ajan kaydı, iş kuyruğu, CVE motoru, paket deposu, raporlama |
| **BER Relay** (`relay/`) | Go | Şube/segment için önbellekleyen dağıtım noktası (Aşama 7) |
| **BER Agent** (`agent/`) | Go, tek binary | Envanter, yama tespiti, iş yürütme, heartbeat. Windows servisi / macOS `launchd` daemon'ı |
| **BER Console** (`console/`) | React + TypeScript + Vite | Tarayıcı tabanlı yönetim arayüzü |
| **Tanıtım sayfası** (`landing/`) | Statik HTML/CSS | GitHub Pages (Aşama 8) |
| **Ortak kod** (`shared/`) | Go | Ajan ↔ sunucu protokol tipleri, sürüm bilgisi |
| **Tasarım token'ları** (`design/`) | CSS | Konsol ve tanıtım sayfasının ortak renk/ölçü değişkenleri |

### Teknoloji seçimi gerekçeleri

- **Go (ajan, sunucu, relay):** Tek statik binary, çapraz derleme (Windows/macOS, amd64/arm64), düşük bellek, güçlü standart TLS kütüphanesi. Sunucu ile ajan aynı dilde olduğu için protokol tipleri (`shared/protocol`) paylaşılır.
- **Standart `net/http` yönlendirici:** Go 1.22+ ile metot ve yol parametresi desteği geldiği için harici router bağımlılığı yok.
- **PostgreSQL 14+:** `gen_random_uuid()`, JSONB, dizi tipleri ve güvenilir transaction desteği.
- **Kendi migration çalıştırıcısı:** Gömülü (`embed`) SQL dosyaları, `pg_advisory_lock` ile eşzamanlı çalışmaya karşı korumalı. Harici bağımlılık gerektirmez.

## 2. Portlar

| Port | Dinleyen | Amaç | Kimlik doğrulama |
|---|---|---|---|
| `8443/tcp` | Server | Konsol (UI + `/api/v1`) | Oturum çerezi + CSRF token |
| `52311/tcp` | Server, Relay | Ajan API (`/agent/v1`) | mTLS (kayıt hariç) |
| `52311/udp` | Agent | Uyandırma bildirimi (Aşama 4) | İmzalı paket |

## 3. Güvenlik modeli

### 3.1 İç sertifika otoritesi (CA)

Sunucu ilk açılışta `data_dir/pki/` altında ECDSA P-256 bir kök CA üretir (10 yıl). Bu CA:

- Ajan API'sinin TLS sertifikasını imzalar (her açılışta yeniden üretilir, CA zinciriyle birlikte sunulur).
- Her ajan için istemci sertifikası imzalar (`CN = ajan UUID`, `ExtKeyUsage = ClientAuth`, 1 yıl).
- Konsol için ayrı bir sertifika verilmezse konsol sertifikasını da imzalar.

CA'nın SHA-256 parmak izi (`sha256:<hex>`) **kurulum parametresi** olarak ajana verilir. Ajan ilk bağlantıda sunucunun sunduğu zincirde bu parmak izine sahip CA'yı arar ve sunucu sertifikasını o CA'ya göre doğrular. Böylece ajan, önceden CA dosyası dağıtılmadan güvenli şekilde kaydolur (kubeadm "discovery token CA hash" yaklaşımı).

### 3.2 Ajan kaydı (enrollment)

```
Ajan                                         Sunucu (:52311)
 │ 1. ECDSA anahtar çifti üret (yerel, 0600)
 │ 2. TLS el sıkışma ─────────────────────────▶ zincir: [sunucu sert., CA]
 │ 3. CA parmak izini pin ile karşılaştır
 │ 4. POST /agent/v1/enroll
 │    { kayıt anahtarı, CSR, host bilgisi } ──▶ 5. Anahtarı doğrula (hash, süre,
 │                                              kullanım sayısı, iptal)
 │                                           6. CSR imzasını doğrula, CN'yi
 │                                              yeni ajan UUID'si ile değiştir
 │                                           7. machines kaydı (active / pending)
 │ ◀────────────── { ajan ID, sertifika, CA }   8. Audit log
 │ 9. Sertifikayı ve CA'yı kaydet, kayıt anahtarını yapılandırmadan sil
 │
 │ POST /agent/v1/heartbeat (mTLS) ──────────▶ CN → ajan ID, seri no. eşleşmesi,
 │ ◀────────────── { durum, sonraki aralık }    durum kontrolü, last_seen güncelle
```

- Kayıt anahtarları veritabanında yalnızca **SHA-256 özeti** olarak tutulur; düz metin yalnızca oluşturulduğu anda bir kez gösterilir.
- Anahtar "yönetici onayı gerektirir" olarak işaretlenmişse makine `pending` durumunda kaydolur. Heartbeat kabul edilir ancak onaylanana kadar iş gönderilmez.
- Sunucu, heartbeat'te sunulan sertifikanın seri numarasını makine kaydındaki seri ile karşılaştırır. Reddedilen/iptal edilen makinelerin sertifikası CRL gerekmeden geçersiz olur.

### 3.3 Konsol kimlik doğrulama

- Yerel kullanıcılar (kurtarma admin dahil) **Argon2id** ile özetlenmiş parola kullanır. AD kullanıcıları Aşama 5'te LDAPS ile doğrulanır.
- Oturum: 256 bit rastgele token, `__Host-ber_session` çerezi (`HttpOnly`, `Secure`, `SameSite=Strict`). Veritabanında yalnızca token'ın SHA-256 özeti saklanır.
- Boşta kalma zaman aşımı (varsayılan 30 dk) ve mutlak oturum süresi (varsayılan 12 saat).
- CSRF: Durum değiştiren her istek, oturuma bağlı `X-CSRF-Token` başlığını taşımalıdır. Ayrıca JSON gövdeli isteklerde `Content-Type: application/json` zorunludur.
- Giriş denemeleri IP ve kullanıcı adı bazında sınırlandırılır (varsayılan 15 dakikada 5 başarısız deneme).
- Güvenlik başlıkları: CSP (`default-src 'self'`), HSTS, `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors 'none'`.

### 3.4 Yetkilendirme (RBAC)

İzinler granülerdir (`machines.read`, `actions.run_command`, `remote.registry.write` …) ve **her API uç noktasında sunucu tarafında** kontrol edilir. Roller izin kümeleridir; Aşama 5'te kapsam (OU / grup) kısıtları ve özel roller eklenir. Ayrıntı: [roller-ve-yetkiler.md](roller-ve-yetkiler.md) (Aşama 5).

### 3.5 Aksiyon imzası (Aşama 4)

Her iş manifesti sunucunun ayrı bir imzalama anahtarı (Ed25519) ile imzalanır. Manifest; dosya listesini, her dosyanın SHA-256 özetini, komutları, son geçerlilik tarihini ve hedef ajan ID'sini içerir. Ajan imzayı ve dosya özetlerini doğrulamadan hiçbir şey çalıştırmaz.

## 4. İçerik modeli: BER Fix

BigFix Fixlet kavramının karşılığıdır.

```yaml
id: ber-fix-chrome-130.0.6723.92-win
title: Google Chrome 130.0.6723.92 güncellemesi
platform: windows
vendor: Google
severity: critical
cves: [CVE-2024-10487, CVE-2024-10488]
restart_required: false
relevance:            # hangi makinede gerekli
  all:
    - app_installed: { name_regex: "^Google Chrome$" }
    - app_version_lt: { name_regex: "^Google Chrome$", version: "130.0.6723.92" }
action:
  files:
    - name: googlechromestandaloneenterprise64.msi
      sha256: "…"
  command: msiexec /i googlechromestandaloneenterprise64.msi /qn /norestart
  shell: cmd
  timeout: 30m
success:              # kurulum sonrası yeniden değerlendirme
  all:
    - app_version_gte: { name_regex: "^Google Chrome$", version: "130.0.6723.92" }
```

Uygunluk kuralları sunucuda envantere karşı değerlendirilir (merkezi değerlendirme). Ajan, başarı kriterini kurulumdan sonra yerel envanteri yeniden toplayarak doğrular. Ayrıntılı kural dili Aşama 3–4'te tanımlanır.

## 5. Ajan çalışma modeli

- **Heartbeat:** Varsayılan 60 sn, ±%10 rastgele sapma (jitter). Hata durumunda üstel geri çekilme (en fazla 15 dk).
- **Tam envanter:** Varsayılan 24 saatte bir, jitter ile. Arada yalnızca değişiklik (delta) gönderilir (Aşama 2).
- **Kaynak kısıtlama:** Taramalar düşük öncelikte. Windows'ta `BELOW_NORMAL`/`IDLE` öncelik ve Job Object CPU sınırı, macOS'ta `nice` + `taskpolicy -b` (Aşama 2).
- **Veri dizini:**
  - Windows: `%ProgramData%\BER\Agent`
  - macOS: `/Library/Application Support/BER/Agent`
- **Loglar:** `<veri dizini>/logs/agent.log`, 10 MB × 5 dosya döngüsel.

### 5.1 Envanter akışı (Aşama 2)

```
 Zamanlayıcı (scanner)                         Sunucu
 ├─ tam tarama (24 sa ± %10)  ─┐
 ├─ değişiklik taraması (4 sa) ─┼─▶ Collect ─▶ önbellek (bölüm + SHA-256)
 └─ konsol isteği / tam istek ─┘                 │
                                                 ▼
             yalnızca özeti değişen bölümler ─▶ POST /agent/v1/inventory (gzip, mTLS)
                                                 │
 heartbeat { inventory_hashes } ───────────────▶ özet karşılaştırma
            ◀── { settings, request_full_inventory, scan_requested_at }
```

| Bölüm | Windows | macOS |
|---|---|---|
| İşletim sistemi | Kayıt defteri (`CurrentVersion`, UBR), CIM (donanım, etki alanı, son açılış), GP durumu (AD DN), bekleyen yeniden başlatma anahtarları | `sw_vers`, `sysctl`, `ioreg` (seri no.) |
| Kurulu yamalar | `Win32_QuickFixEngineering` | `InstallHistory.plist` |
| Eksik yamalar | Windows Update Agent (`IUpdateSearcher`), çevrimiçi veya `wsusscn2.cab` ile çevrimdışı | `softwareupdate --list` |
| Uygulamalar | Uninstall anahtarları (HKLM 64/32, HKU), MSI, AppX | `.app` paketleri (`Info.plist`), pkg makbuzları, Homebrew |

### 5.2 CVE motoru (Aşama 3)

```
 KEV · EPSS · MSRC · NVD ──▶ cve.Syncer (24 sa, artımlı) ──▶ cves, cve_cpe_matches, msrc_remediations, kev, epss
                                                                 │
 envanter geldi ─▶ vuln.Engine kuyruğu ─▶ cve.Correlate ◀────────┘
                     (eşitleme / kural değişikliği sonrası tüm filo)
                         │  Windows: yapı < MSRC FixedBuild, eksik KB → CVE
                         │  macOS:   sürüm ∈ NVD apple:macos aralığı
                         │  Uygulama: sözlük → CPE → sürüm ∈ NVD aralığı
                         ▼
               machine_vulnerabilities (+ risk) ─▶ machine_risk, compliance_snapshots
```

Ayrıntılar, risk formülü ve çevrimdışı mod: [cve.md](cve.md).

## 6. Veritabanı şeması

Şema aşamalarla genişler. Her aşama yeni numaralı migration ekler (`server/internal/store/migrations/`).

### Aşama 1 (bu sürüm)

| Tablo | Amaç | Önemli alanlar |
|---|---|---|
| `schema_migrations` | Uygulanan migration'lar | `version`, `applied_at` |
| `users` | Konsol kullanıcıları (yerel + AD) | `username` (küçük harf benzersiz), `source`, `password_hash`, `role`, `is_recovery`, `totp_secret_enc`, `disabled` |
| `sessions` | Konsol oturumları | `token_hash` (PK), `user_id`, `csrf_token`, `last_seen_at`, `expires_at` |
| `registration_keys` | Ajan kayıt anahtarları | `key_hash` (benzersiz), `key_prefix`, `require_approval`, `max_uses`, `use_count`, `expires_at`, `revoked_at` |
| `machines` | Kayıtlı ajanlar / makineler | `id` (= ajan ID), `hostname`, `status`, `os_*`, `agent_version`, `cert_serial`, `cert_fingerprint`, `last_seen_at` |
| `audit_log` | Değiştirilemez denetim kaydı | `occurred_at`, `actor_*`, `action`, `target_*`, `params` (JSONB), `result`; UPDATE/DELETE/TRUNCATE trigger ile engelli |

### Aşama 2

| Tablo | Amaç | Önemli alanlar |
|---|---|---|
| `machine_inventory` | Makine başına envanter özeti ve sayaçlar | `os` (JSONB), `hashes` (bölüm özetleri), `last_full_at`, `missing_scan_source`, `missing_count`, `missing_critical_count`, `app_count`, `reboot_pending` |
| `installed_patches` | Kurulu yamalar | `(machine_id, patch_id)` PK, `installed_on`, `source` |
| `missing_patches` | Eksik güncellemeler | `(machine_id, update_id)` PK, `kb`, `classification`, `severity`, `cves` (GIN indeksli), `reboot_required` |
| `installed_apps` | Üçüncü parti uygulamalar | `name`, `version`, `publisher`, `source`, `identifier`, `scope` |
| `agent_settings` | Filo geneli ajan ayarları (tek satır) | `settings` (JSONB) |
| `machines` (ek) | Konsoldan istenen tarama | `scan_requested_at` |

### Aşama 3

| Tablo | Amaç | Önemli alanlar |
|---|---|---|
| `cves` | CVE kayıtları (NVD + MSRC) | `id`, `source`, `title`, `description`, `cvss_score`, `cvss_vector`, `severity`, `cwes`, `msrc_exploited` |
| `cve_cpe_matches` | NVD savunmasız ürün aralıkları | `(vendor, product)` indeksli, `version`, `version_start_*`, `version_end_*` |
| `msrc_remediations` | Windows düzeltmeleri | `cve_id`, `kb`, `build_family`, `fixed_build`, `severity` |
| `kev`, `epss` | CISA KEV ve FIRST EPSS | `date_added`, `due_date`, `ransomware` / `score`, `percentile` |
| `feed_status` | Kaynak eşitleme durumu | `last_success_at`, `last_error`, `state` (artımlı eşitleme imleci) |
| `app_cpe_rules` | Özel uygulama → CPE kuralları | `name_pattern`, `publisher_pattern`, `identifier_pattern`, `vendor`, `product` |
| `machine_vulnerabilities` | Makine × CVE bulguları | `sources`, `refs`, `fixed_by`, `risk_score`, `first_seen_at` |
| `machine_risk` | Makine risk özeti | `vuln_count`, `critical_count`, `kev_count`, `max_risk` |
| `compliance_snapshots` | Günlük uyumluluk özeti | `day`, `fully_patched`, `kev_machines`, `avg_risk` |

### Sonraki aşamalar (plan)

| Aşama | Tablolar |
|---|---|
| 4 – Dağıtım | `packages`, `package_files`, `ber_fixes`, `actions`, `action_targets` (hedef başına durum), `action_results` (stdout/stderr/çıkış kodu), `transfer_limits` |
| 5 – AD / RBAC | `ad_settings` (şifreli bağlantı parolası), `ad_group_role_mappings`, `roles`, `role_permissions`, `role_scopes`, `ad_computers`, `api_keys` |
| 6 – Uzaktan yönetim | `remote_feature_settings` (makine/grup bazında opt-in), `registry_backups`, `perf_samples` |
| 7 – Gelişmiş dağıtım | `relays`, `maintenance_windows`, `rollout_rings`, `restart_policies`, `notification_channels`, `notification_rules` |
| Gruplar (2–5) | `groups` (statik / OU / dinamik kural), `group_members`, `tags`, `machine_tags` |

## 7. Klasör yapısı

```
agent/                 Ajan (cmd/ber-agent, cmd/ber-agentsim, internal/…)
server/                Sunucu (cmd/ber-server, internal/…, api/openapi.yaml)
relay/                 Relay (Aşama 7)
shared/                Ortak Go paketleri (protocol, version)
console/               React + TS + Vite konsol
design/                Ortak tasarım token'ları (tokens.css)
landing/               Tanıtım sayfası (Aşama 8)
installers/windows/    WiX MSI kaynakları (Aşama 8)
installers/macos/      pkg, launchd plist, PPPC profili (Aşama 8)
deploy/                Docker Compose ve geliştirme ortamı
docs/                  Türkçe dokümantasyon
.github/workflows/     CI/CD
```

Go kodu kökte tek bir modüldür (`go.mod`). Ajan binary'si yalnızca kullandığı paketleri derlediği için sunucu bağımlılıkları ajan boyutunu etkilemez.
