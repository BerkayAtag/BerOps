# Değişiklik Günlüğü

Bu projedeki tüm önemli değişiklikler bu dosyada belgelenir.
Biçim [Keep a Changelog](https://keepachangelog.com/tr-TR/1.1.0/) esas alınarak hazırlanmıştır ve proje [Anlamsal Sürümleme](https://semver.org/lang/tr/) kullanır.

## [Yayımlanmamış]

### Eklendi — Aşama 2: Envanter ve tespit

- Ajan envanteri: işletim sistemi ve donanım, yama seviyesi, kurulu yamalar, eksik güncellemeler ve üçüncü parti uygulamalar (Windows ve macOS).
- Windows: kayıt defteri (64/32 bit, kullanıcı hive'ları), MSI ve AppX uygulamaları; Windows Update Agent ile çevrimiçi ve `wsusscn2.cab` ile çevrimdışı eksik güncelleme taraması (KB, sınıflandırma, MSRC önemi, CVE); AD OU ve bekleyen yeniden başlatma tespiti.
- macOS: `.app` paketleri, pkg makbuzları, Homebrew; `softwareupdate --list` ile eksik güncellemeler; kurulum geçmişinden kurulu güncellemeler.
- Kaynak kısıtlama: Windows'ta Job Object CPU sert sınırı ve düşük öncelik, macOS'ta arka plan QoS; ajan içi CPU bütçesi; pil ve kullanıcı etkinliğinde erteleme.
- Tarama zamanlayıcısı: tam (24 sa) ve değişiklik (4 sa) taramaları, jitter, bölüm özetleriyle yalnızca değişenlerin gönderilmesi, başarısız yüklemelerin yeniden denenmesi, sunucunun tam envanter isteği.
- Sunucu: `machine_inventory`, `installed_patches`, `missing_patches`, `installed_apps`, `agent_settings` tabloları; gzip envanter yükleme; Range destekli katalog indirme; heartbeat'te ayar ve tarama talimatları.
- Konsol API'si: filtreli/sıralı/sayfalı makine listesi, filo özeti, makine detayı ve alt listeleri, toplu yeniden tarama, ajan ayarları.
- Konsol: makine listesi (arama, filtre, sıralama, sayfalama, toplu seçim), makine detay sayfası, gösterge panelinde uyumluluk ve dağılım, ajan ayarları sayfası.
- `ber-agent inventory` tanılama komutu; simülatöre gerçekçi sahte envanter.

### Eklendi — Aşama 1: Temel altyapı

- Monorepo iskeleti (`agent/`, `server/`, `relay/`, `console/`, `design/`, `landing/`, `installers/`, `docs/`) ve tek Go modülü.
- Mimari dokümanı, veritabanı şeması planı ve varsayımlar belgesi.
- PostgreSQL şeması: `users`, `sessions`, `registration_keys`, `machines`, `audit_log` (değiştirilemez); gömülü migration çalıştırıcısı.
- Sunucunun iç sertifika otoritesi (ECDSA P-256): ajan API'si için sunucu sertifikası, ajan CSR imzalama.
- Ajan kaydı: kayıt anahtarı (kullanım sayısı, süre, yönetici onayı), CA parmak izi pin'i ile ilk güven.
- mTLS heartbeat: sertifika seri numarası kontrolü, reddedilen makinelerin engellenmesi.
- Konsol API'si: giriş/çıkış, oturum (Argon2id, `__Host-` çerez, CSRF, boşta kalma zaman aşımı), giriş hız sınırı, güvenlik başlıkları (CSP, HSTS).
- Granüler izinler ve Admin / Teknisyen / Salt Okunur rolleri; reddedilen istekler denetim kaydına yazılır.
- OpenAPI 3.1 tanımı (`/api/openapi.yaml`).
- `ber-server` komutları: `serve`, `migrate`, `admin create`, `regkey create`, `version`.
- `ber-agent` (Windows servisi desteğiyle): `configure`, `enroll`, `run`, `status`, `version`; jitter ve üstel geri çekilmeli heartbeat, döngüsel log dosyaları.
- `ber-agentsim`: çok sayıda sanal ajanı simüle eden test aracı.
- Konsol: giriş ekranı, gösterge paneli iskeleti, Türkçe/İngilizce, açık/karanlık tema; ortak tasarım token'ları (`design/tokens.css`).
- GitHub Actions: Go lint/test/govulncheck, Windows ve macOS ajan testleri, çapraz derleme, konsol lint/test/derleme, CodeQL, bağımlılık incelemesi, Dependabot.
