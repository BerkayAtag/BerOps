# Değişiklik Günlüğü

Bu projedeki tüm önemli değişiklikler bu dosyada belgelenir.
Biçim [Keep a Changelog](https://keepachangelog.com/tr-TR/1.1.0/) esas alınarak hazırlanmıştır ve proje [Anlamsal Sürümleme](https://semver.org/lang/tr/) kullanır.

## [Yayımlanmamış]

### Eklendi — Aşama 3: CVE motoru ve raporlar

- CVE kaynakları:
  - CISA KEV, FIRST EPSS, Microsoft MSRC (CVRF) ve NVD CVE API 2.0 eşitleyicisi.
  - Artımlı NVD eşitlemesi, hız sınırına uyum ve yeniden deneme.
  - Değişen MSRC belgelerinin yeniden işlenmesi.
  - İnternet erişimi olmayan ortamlar için çevrimdışı klasör modu.
  - `ber-server cve sync` komutu.
- Korelasyon motoru:
  - Windows yapı numarası ↔ MSRC `FixedBuild` karşılaştırması.
  - Eksik KB → CVE eşlemesi.
  - macOS sürümü ve üçüncü parti uygulamalar için NVD CPE sürüm aralıkları.
  - NVD'ye karşı doğrulanmış ürün sözlüğü; konsoldan özel uygulama → CPE kuralları.
- Risk skoru (CVSS, EPSS, KEV, fidye yazılımı), makine risk özeti ve günlük uyumluluk anlık görüntüleri.
- Veritabanı tabloları: `cves`, `cve_cpe_matches`, `msrc_remediations`, `kev`, `epss`, `feed_status`, `app_cpe_rules`, `machine_vulnerabilities`, `machine_risk`, `compliance_snapshots`.
- Konsol API'si:
  - Zafiyet listesi ve CVE detayı.
  - Makine zafiyetleri.
  - Gösterge paneli risk özeti.
  - CVE kaynak durumu, eşitleme ve kurallar.
  - Rapor dışa aktarma.
  - Makine listesinde risk ve açık sayısı sütunları ile sıralaması.
- Raporlar:
  - Dört rapor: uyumluluk, zafiyet, eksik yama ve uygulama envanteri.
  - Biçimler: PDF (Türkçe karakter destekli, marka renkli), Excel (XLSX) ve CSV (UTF-8 BOM, formül enjeksiyonu koruması).
  - Türkçe ve İngilizce, kullanıcının saat diliminde.
- Konsol:
  - Güvenlik Açıkları ve CVE detay sayfaları.
  - Makine detayında risk kartları ve açık sekmesi.
  - Gösterge panelinde risk bölümü, önem dağılımı, uyumluluk eğilimi, en riskli açıklar ve makineler.
  - Raporlar sayfası ve CVE kaynakları ayar sayfası.

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
